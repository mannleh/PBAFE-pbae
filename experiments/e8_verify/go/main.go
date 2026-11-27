// E8: independent second verification core (Go, crypto/ed25519 + crypto/sha256).
// Reads cases.json produced by build_cases.py and re-derives every decision
// without importing any Python code. Differential pass = identical outcome and
// identical per-record outcomes for every fixture and tampered variant.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
)

const (
	version    = "PBA/2"
	maxCoord   = int64(1000000000)
	maxCount   = int64(1000000)
	maxClients = int64(10000)
	pass       = "PASS"
	failRoster = "FAIL_ROSTER"
	failPolicy = "FAIL_POLICY"
	failReplay = "FAIL_RESULT_REPLAY"
	inconcl    = "INCONCLUSIVE_EVIDENCE"
)

type Trust struct {
	SelectionKey string            `json:"selection_key"`
	ServerKey    string            `json:"server_key"`
	Registry     map[string]string `json:"registry"`
	RoundID      int64             `json:"round_id"`
	ModelHash    string            `json:"model_hash"`
	BulletinPin  string            `json:"bulletin_pin"`
	SnapshotPin  string            `json:"snapshot_pin"`
}

type Expected struct {
	Outcome string            `json:"outcome"`
	Records map[string]string `json:"records"`
}

type Fixture struct {
	ID       string            `json:"id"`
	Full     bool              `json:"full"`
	Slots    []int             `json:"slots"`
	Trust    Trust             `json:"trust"`
	Source   map[string]string `json:"source"`
	Expected Expected          `json:"expected"`
}

type Mutant struct {
	ID       string             `json:"id"`
	Base     string             `json:"base"`
	Full     bool               `json:"full"`
	Slots    []int              `json:"slots"`
	Trust    Trust              `json:"trust"`
	Diff     map[string]*string `json:"diff"`
	Expected Expected           `json:"expected"`
}

type Bases struct {
	ID     string            `json:"id"`
	Source map[string]string `json:"source"`
}

type Cases struct {
	Fixtures []Fixture `json:"fixtures"`
	Mutants  []Mutant  `json:"mutants"`
	Bases    []Bases   `json:"bases"`
}

type Fault struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

func (f *Fault) Error() string { return f.Reason }

// ---------- canonical JSON ----------

func canon(v interface{}) []byte {
	var b bytes.Buffer
	writeCanon(&b, v)
	return b.Bytes()
}

func writeCanon(b *bytes.Buffer, v interface{}) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		b.WriteString(x.String())
	case float64:
		b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case map[string]interface{}:
		b.WriteByte('{')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeCanon(b, x[k])
		}
		b.WriteByte('}')
	case []interface{}:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanon(b, e)
		}
		b.WriteByte(']')
	default:
		panic(fmt.Sprintf("unsupported json type %T", v))
	}
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				fmt.Fprintf(b, "\\u%04x", r)
			} else if r > 0x7e {
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(b, "\\u%04x\\u%04x", 0xd800+(r>>10), 0xdc00+(r&0x3ff))
				} else {
					fmt.Fprintf(b, "\\u%04x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func parseJSON(raw []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

// ---------- digest / signatures ----------

func digestHex(domain string, parts ...[]byte) string {
	h := sha256.New()
	writePart(h, []byte(domain))
	for _, p := range parts {
		writePart(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type partWriter interface{ Write([]byte) (int, error) }

func writePart(w partWriter, p []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(p)))
	w.Write(l[:])
	w.Write(p)
}

func verifyEnvelope(pubHex, domain string, envelope map[string]interface{}) (map[string]interface{}, error) {
	body, ok := envelope["body"].(map[string]interface{})
	if !ok {
		return nil, &Fault{failRoster, "malformed envelope body"}
	}
	sigHex, ok := envelope["sig"].(string)
	if !ok {
		return nil, &Fault{failRoster, "malformed signature"}
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, &Fault{failRoster, "bad public key"}
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, &Fault{failRoster, "bad signature encoding"}
	}
	msg, err := hex.DecodeString(digestHex(domain, canon(body)))
	if err != nil {
		return nil, &Fault{failRoster, "bad digest"}
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return nil, &Fault{failRoster, "signature"}
	}
	return body, nil
}

// ---------- merkle ----------

func nodeHex(left, right string) string {
	l, _ := hex.DecodeString(left)
	r, _ := hex.DecodeString(right)
	return digestHex("PBA2/node", l, r)
}

func leafHex(obj map[string]interface{}) string {
	return digestHex("PBA2/leaf", canon(obj))
}

func checkProof(valueHex string, index, count int, proof []string, root string) bool {
	if index < 0 || index >= count {
		return false
	}
	bits := 0
	for c := count - 1; c > 0; c >>= 1 {
		bits++
	}
	if len(proof) != bits {
		return false
	}
	h, width := valueHex, count
	for _, sib := range proof {
		if width%2 == 1 && index == width-1 && sib != h {
			return false
		}
		left, right := h, sib
		if index%2 == 1 {
			left, right = sib, h
		}
		h = nodeHex(left, right)
		index /= 2
		width = (width + 1) / 2
	}
	return h == root
}

func treeRoot(leaves []string) string {
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for j := 0; j < len(level); j += 2 {
			k := j + 1
			if k >= len(level) {
				k = len(level) - 1
			}
			next = append(next, nodeHex(level[j], level[k]))
		}
		level = next
	}
	if len(level) == 0 {
		return ""
	}
	return level[0]
}

// ---------- reader ----------

type Reader struct {
	source map[string][]byte
}

func (r *Reader) raw(name string) ([]byte, error) {
	raw, ok := r.source[name]
	if !ok {
		return nil, &Fault{inconcl, "missing:" + name}
	}
	return raw, nil
}

func (r *Reader) value(name string) (interface{}, error) {
	raw, err := r.raw(name)
	if err != nil {
		return nil, err
	}
	v, perr := parseJSON(raw)
	if perr != nil {
		return nil, &Fault{failRoster, "malformed:" + name}
	}
	if !bytes.Equal(canon(v), raw) {
		return nil, &Fault{failRoster, "malformed:" + name}
	}
	return v, nil
}

func (r *Reader) obj(name string) (map[string]interface{}, error) {
	v, err := r.value(name)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return nil, &Fault{failRoster, "malformed:" + name}
	}
	return obj, nil
}

func getInt(m map[string]interface{}, key string) (int64, bool) {
	n, ok := m[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
}

func getStr(m map[string]interface{}, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

func isNull(m map[string]interface{}, key string) bool {
	return m[key] == nil
}

// ---------- audit ----------

type Result struct {
	Outcome string
	Records map[int]string
	Findings []Fault
}

func require(cond bool, outcome, reason string) error {
	if !cond {
		return &Fault{outcome, reason}
	}
	return nil
}

func audit(source map[string][]byte, t Trust, slots []int, full bool) Result {
	res := Result{Outcome: pass, Records: map[int]string{}}
	add := func(f *Fault) { res.Findings = append(res.Findings, *f) }
	r := &Reader{source: source}

	bulletinObj, err := r.obj("bulletin")
	if err != nil {
		add(err.(*Fault))
		return finish(&res)
	}
	if digestHex("PBA2/bulletin", canon(bulletinObj)) != t.BulletinPin {
		add(&Fault{failRoster, "bulletin pin"})
		return finish(&res)
	}
	bulletin, err := verifyEnvelope(t.SelectionKey, "PBA2/selection", bulletinObj)
	if err != nil {
		add(err.(*Fault))
		return finish(&res)
	}
	round, ok1 := getInt(bulletin, "round")
	k, ok2 := getInt(bulletin, "K")
	dim, ok3 := getInt(bulletin, "dimension")
	mh, ok4 := getStr(bulletin, "model_hash")
	ver, ok5 := getStr(bulletin, "version")
	if err := require(ok1 && ok2 && ok3 && ok4 && ok5 && round == t.RoundID && mh == t.ModelHash &&
		ver == version && k > 0 && k <= maxClients && dim > 0 && dim <= 1000000,
		failRoster, "bulletin context/domain"); err != nil {
		add(err.(*Fault))
		return finish(&res)
	}

	snapObj, err := r.obj("snapshot")
	if err != nil {
		add(err.(*Fault))
		return finish(&res)
	}
	if digestHex("PBA2/snapshot", canon(snapObj)) != t.SnapshotPin {
		add(&Fault{failRoster, "snapshot pin"})
		return finish(&res)
	}
	snapshot, err := verifyEnvelope(t.ServerKey, "PBA2/server", snapObj)
	if err != nil {
		add(err.(*Fault))
		return finish(&res)
	}
	bh, ok1 := getStr(snapshot, "bulletin_hash")
	sk, ok2 := getInt(snapshot, "K")
	den, ok3 := getInt(snapshot, "denominator")
	if err := require(ok1 && ok2 && ok3 && bh == t.BulletinPin && sk == k &&
		den > 0 && den <= maxClients*maxCount, failRoster, "snapshot context/length"); err != nil {
		add(err.(*Fault))
		return finish(&res)
	}

	policy, err := r.obj("policy")
	if err != nil {
		add(err.(*Fault))
		return finish(&res)
	}
	ph, _ := getStr(bulletin, "policy_hash")
	if digestHex("PBA2/policy", canon(policy)) != ph {
		add(&Fault{failRoster, "policy digest"})
		return finish(&res)
	}
	if pv, _ := getStr(policy, "version"); pv != "declared-fedavg-v2" || len(policy) != 3 {
		add(&Fault{failPolicy, "unsupported policy"})
		return finish(&res)
	}
	if mc, ok := getInt(policy, "max_count"); !ok || mc != maxCount {
		add(&Fault{failPolicy, "unsupported policy"})
		return finish(&res)
	}
	if sr, _ := getStr(policy, "status_rule"); sr != "valid-submissions-accepted;independent-close-for-absence" {
		add(&Fault{failPolicy, "unsupported policy"})
		return finish(&res)
	}

	chosen := slots
	if full {
		chosen = make([]int, int(k))
		for i := range chosen {
			chosen[i] = i
		}
	}
	seen := map[int]bool{}
	for _, s := range chosen {
		if s < 0 || int64(s) >= k || seen[s] {
			add(&Fault{failRoster, "invalid audit selection"})
			return finish(&res)
		}
		seen[s] = true
	}
	var rosterLeaves, stateLeaves []string
	var clientIDs []int64
	var vectors [][]int64
	var nums []int64

	for _, slot := range chosen {
		err := recordCheck(r, t, bulletin, snapshot, policy, slot, res.Findings, &rosterLeaves, &stateLeaves,
			&clientIDs, &vectors, &nums, full)
		if err != nil {
			f := err.(*Fault)
			res.Records[slot] = f.Outcome
			res.Findings = append(res.Findings, *f)
		} else {
			res.Records[slot] = pass
		}
	}

	if full && len(res.Findings) == 0 {
		root, _ := getStr(bulletin, "roster_root")
		sroot, _ := getStr(snapshot, "state_root")
		if err := require(int64(len(uniqueIDs(clientIDs))) == k && treeRoot(rosterLeaves) == root &&
			treeRoot(stateLeaves) == sroot, failRoster, "full set mismatch"); err != nil {
			add(err.(*Fault))
		} else {
			var sum int64
			for _, n := range nums {
				sum += n
			}
			if err := require(len(nums) > 0 && sum == den, failPolicy, "global normalization"); err != nil {
				add(err.(*Fault))
			} else {
				rawResult, err := r.raw("result")
				if err != nil {
					add(err.(*Fault))
				} else if digestHex("PBA2/result", rawResult) != strOf(snapshot, "result_digest") {
					add(&Fault{failReplay, "result commitment"})
				} else if _, derr := decodeVector(rawResult, int(dim)); derr != nil {
					add(&Fault{failRoster, "malformed result"})
				} else {
					expected, rerr := encodeReplay(vectors, nums, den, int(dim))
					if rerr != nil || !bytes.Equal(rawResult, expected) {
						add(&Fault{failReplay, "replay mismatch"})
					}
				}
			}
		}
	}
	return finish(&res)
}

func strOf(m map[string]interface{}, key string) string {
	s, _ := getStr(m, key)
	return s
}

func uniqueIDs(ids []int64) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	for _, v := range ids {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func finish(res *Result) Result {
	for _, o := range []string{failRoster, failPolicy, failReplay, inconcl} {
		for _, f := range res.Findings {
			if f.Outcome == o {
				res.Outcome = o
				return *res
			}
		}
	}
	res.Outcome = pass
	return *res
}

func recordCheck(r *Reader, t Trust, bulletin, snapshot, policy map[string]interface{}, slot int,
	findings []Fault, rosterLeaves, stateLeaves *[]string, clientIDs *[]int64, vectors *[][]int64, nums *[]int64, full bool) error {
	prefix := "record/" + strconv.Itoa(slot) + "/"
	roster, err := r.obj(prefix + "roster")
	if err != nil {
		return err
	}
	rpv, err := r.value(prefix + "roster_proof")
	if err != nil {
		return err
	}
	proof, err := asStrings(rpv)
	if err != nil {
		return &Fault{failRoster, "malformed roster proof"}
	}
	rs, _ := getInt(roster, "slot")
	k, _ := getInt(bulletin, "K")
	root, _ := getStr(bulletin, "roster_root")
	if rs != int64(slot) || !checkProof(leafHex(roster), slot, int(k), proof, root) {
		return &Fault{failRoster, "roster membership"}
	}
	cid, ok := getInt(roster, "client_id")
	if !ok {
		return &Fault{failRoster, "unregistered identity"}
	}
	if _, ok := t.Registry[strconv.FormatInt(cid, 10)]; !ok {
		return &Fault{failRoster, "unregistered identity"}
	}
	state, err := r.obj(prefix + "state")
	if err != nil {
		return err
	}
	spv, err := r.value(prefix + "state_proof")
	if err != nil {
		return err
	}
	proof2, err := asStrings(spv)
	if err != nil {
		return &Fault{failRoster, "malformed state proof"}
	}
	sroot, _ := getStr(snapshot, "state_root")
	if !checkProof(leafHex(state), slot, int(k), proof2, sroot) {
		return &Fault{failRoster, "state membership"}
	}
	ss, _ := getInt(state, "slot")
	scid, _ := getInt(state, "client_id")
	if ss != int64(slot) || scid != cid {
		return &Fault{failRoster, "slot identity"}
	}
	status, _ := getStr(state, "status")
	switch status {
	case "ACCEPTED", "REJECTED", "TIMEOUT", "ABSENT":
	default:
		return &Fault{failRoster, "unknown status encoding"}
	}
	num, ok := getInt(state, "numerator")
	if !ok || num < 0 || num > maxCount {
		return &Fault{failRoster, "malformed weight numerator"}
	}

	if isNull(state, "receipt_digest") {
		disp, err := r.obj(prefix + "disposition")
		if err != nil {
			return err
		}
		body, verr := verifyEnvelope(t.SelectionKey, "PBA2/disposition", disp)
		if verr != nil {
			return verr
		}
		dbh, _ := getStr(body, "bulletin_hash")
		dcid, _ := getInt(body, "client_id")
		dslot, _ := getInt(body, "slot")
		dstatus, _ := getStr(body, "status")
		if dbh != t.BulletinPin || dcid != cid || dslot != int64(slot) || dstatus != status {
			return &Fault{failRoster, "close observation"}
		}
		if status != "ABSENT" && status != "TIMEOUT" || num != 0 {
			return &Fault{failPolicy, "exclusion rule"}
		}
		if full {
			*rosterLeaves = append(*rosterLeaves, leafHex(roster))
			*stateLeaves = append(*stateLeaves, leafHex(state))
			*clientIDs = append(*clientIDs, cid)
		}
		return nil
	}

	receipt, err := r.obj(prefix + "receipt")
	if err != nil {
		return err
	}
	rd, _ := getStr(state, "receipt_digest")
	if digestHex("PBA2/receipt", canon(receipt)) != rd {
		return &Fault{failRoster, "receipt digest"}
	}
	clientKey := t.Registry[strconv.FormatInt(cid, 10)]
	q, err := verifyEnvelope(clientKey, "PBA2/client", receipt)
	if err != nil {
		return err
	}
	qcid, _ := getInt(q, "client_id")
	qround, _ := getInt(q, "round")
	qmh, _ := getStr(q, "model_hash")
	qbh, _ := getStr(q, "bulletin_hash")
	qver, _ := getStr(q, "version")
	qstatus, _ := getStr(q, "status")
	if qcid != cid || qround != t.RoundID || qmh != t.ModelHash || qbh != t.BulletinPin ||
		qver != version || qstatus != "SUBMITTED" {
		return &Fault{failRoster, "receipt context"}
	}
	count, ok := getInt(q, "declared_count")
	if !ok || count <= 0 || count > maxCount {
		return &Fault{failRoster, "count domain"}
	}
	pvState, _ := getStr(state, "policy_version")
	pcState, _ := getInt(state, "policy_count")
	pvPolicy, _ := getStr(policy, "version")
	if pvState != pvPolicy || pcState != count || num != count || status != "ACCEPTED" {
		return &Fault{failPolicy, "local declaration/weight/status rule"}
	}
	opening, err := r.raw(prefix + "opening")
	if err != nil {
		return err
	}
	updateRaw, err := r.raw(prefix + "update")
	if err != nil {
		return err
	}
	ud, _ := getStr(q, "update_digest")
	if len(opening) != 32 || digestHex("PBA2/update", updateRaw, opening) != ud {
		return &Fault{failRoster, "update opening"}
	}
	vec, derr := decodeVector(updateRaw, int(mustInt(bulletin, "dimension")))
	if derr != nil {
		return &Fault{failRoster, "malformed vector"}
	}
	if full {
		*rosterLeaves = append(*rosterLeaves, leafHex(roster))
		*stateLeaves = append(*stateLeaves, leafHex(state))
		*clientIDs = append(*clientIDs, cid)
		if status == "ACCEPTED" {
			*vectors = append(*vectors, vec)
			*nums = append(*nums, num)
		}
	}
	return nil
}

func mustInt(m map[string]interface{}, key string) int64 {
	v, _ := getInt(m, key)
	return v
}

func asStrings(v interface{}) ([]string, error) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("not an array")
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("non-string proof")
		}
		out = append(out, s)
	}
	return out, nil
}

func decodeVector(raw []byte, dim int) ([]int64, error) {
	if dim <= 0 || len(raw) != dim*8 {
		return nil, fmt.Errorf("incorrect vector length")
	}
	out := make([]int64, dim)
	for i := 0; i < dim; i++ {
		v := int64(binary.BigEndian.Uint64(raw[i*8 : i*8+8]))
		if v > maxCoord || v < -maxCoord {
			return nil, fmt.Errorf("coordinate bound")
		}
		out[i] = v
	}
	return out, nil
}

func encodeReplay(vectors [][]int64, nums []int64, den int64, dim int) ([]byte, error) {
	if len(vectors) == 0 || len(vectors) != len(nums) {
		return nil, fmt.Errorf("missing replay inputs")
	}
	out := make([]byte, dim*8)
	for j := 0; j < dim; j++ {
		sum := big.NewInt(0)
		for i, v := range vectors {
			if len(v) != dim {
				return nil, fmt.Errorf("inconsistent dimension")
			}
			sum.Add(sum, big.NewInt(v[j]*nums[i]))
		}
		q := roundEven(sum, den)
		if q.Cmp(big.NewInt(maxCoord)) > 0 || q.Cmp(big.NewInt(-maxCoord)) < 0 {
			return nil, fmt.Errorf("coordinate bound")
		}
		binary.BigEndian.PutUint64(out[j*8:j*8+8], uint64(q.Int64()))
	}
	return out, nil
}

func roundEven(n *big.Int, d int64) *big.Int {
	neg := n.Sign() < 0
	abs := new(big.Int).Abs(n)
	q, r := new(big.Int).QuoRem(abs, big.NewInt(d), new(big.Int))
	twice := new(big.Int).Lsh(r, 1)
	cmp := twice.Cmp(big.NewInt(d))
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		q.Add(q, big.NewInt(1))
	}
	if neg {
		q.Neg(q)
	}
	return q
}

// ---------- main ----------

func main() {
	casesPath := flag.String("cases", `experiments/e8_verify/cases/cases.json`, "cases json")
	outPath := flag.String("out", `experiments/e8_verify/go_report.json`, "report json")
	flag.Parse()
	raw, err := os.ReadFile(*casesPath)
	if err != nil {
		panic(err)
	}
	var cases Cases
	if err := json.Unmarshal(raw, &cases); err != nil {
		panic(err)
	}
	fixtureSources := map[string]map[string][]byte{}
	check := func(id string, src map[string][]byte, t Trust, slots []int, full bool, exp Expected) map[string]interface{} {
		res := audit(src, t, slots, full)
		mismatch := res.Outcome != exp.Outcome
		recs := map[string]string{}
		for k, v := range res.Records {
			recs[strconv.Itoa(k)] = v
			if exp.Records[strconv.Itoa(k)] != v {
				mismatch = true
			}
		}
		for sk := range exp.Records {
			if _, ok := res.Records[mustAtoi(sk)]; !ok {
				mismatch = true
			}
		}
		return map[string]interface{}{"id": id, "outcome": res.Outcome, "expected": exp.Outcome,
			"records": recs, "mismatch": mismatch, "findings": res.Findings}
	}
	var reports []map[string]interface{}
	passN, failN := 0, 0
	for _, b := range cases.Bases {
		src := map[string][]byte{}
		for k, v := range b.Source {
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				panic(err)
			}
			src[k] = raw
		}
		fixtureSources[b.ID] = src
	}
	for _, f := range cases.Fixtures {
		src := map[string][]byte{}
		for k, v := range f.Source {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				panic(err)
			}
			src[k] = b
		}
		fixtureSources[f.ID] = src
		r := check(f.ID, src, f.Trust, f.Slots, f.Full, f.Expected)
		reports = append(reports, r)
		if r["mismatch"].(bool) {
			failN++
		} else {
			passN++
		}
	}
	for _, m := range cases.Mutants {
		base, ok := fixtureSources[m.Base]
		if !ok {
			panic("missing base " + m.Base)
		}
		src := map[string][]byte{}
		for k, v := range base {
			src[k] = v
		}
		for k, v := range m.Diff {
			if v == nil {
				delete(src, k)
			} else {
				b, err := base64.StdEncoding.DecodeString(*v)
				if err != nil {
					panic(err)
				}
				src[k] = b
			}
		}
		r := check(m.ID, src, m.Trust, m.Slots, m.Full, m.Expected)
		reports = append(reports, r)
		if r["mismatch"].(bool) {
			failN++
		} else {
			passN++
		}
	}
	out := map[string]interface{}{"cases": len(reports), "agreements": passN, "mismatches": failN,
		"reports": reports}
	b, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile(*outPath, b, 0644)
	fmt.Printf("cases=%d agreements=%d mismatches=%d\n", len(reports), passN, failN)
}

func mustAtoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}