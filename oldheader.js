
class Header {
  constructor() {
    this.id = 0;
    this.bits = 0;
    this.qdcount = 0;
    this.ancount = 0;
    this.nscount = 0;
    this.arcount = 0;
  }

  getSize() {
    return 12;
  }

  toWriter(bw) {
    bw.writeU16BE(this.id);
    bw.writeU16BE(this.bits);
    bw.writeU16BE(this.qdcount);
    bw.writeU16BE(this.ancount);
    bw.writeU16BE(this.nscount);
    bw.writeU16BE(this.arcount);
    return bw;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  fromReader(br) {
    this.id = br.readU16BE();
    this.bits = br.readU16BE();
    this.qdcount = br.readU16BE();
    this.ancount = br.readU16BE();
    this.nscount = br.readU16BE();
    this.arcount = br.readU16BE();
    return this;
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  set(mask, val) {
    if (val)
      this.bits |= mask;
    else
      this.bits &= ~mask;
    return this;
  }

  setResponse(val) {
    return this.set(masks.QR, val);
  }

  setOpcode(op) {
    this.bits &= ~(0x0f << 11);
    this.bits |= (op & 0x0f) << 11;
    return this;
  }

  setAuthoritative(val) {
    return this.set(masks.AA, val);
  }

  setTruncated(val) {
    return this.set(masks.TC, val);
  }

  setRecursionDesired(val) {
    return this.set(masks.RD, val);
  }

  setRecursionAvailable(val) {
    return this.set(masks.RA, val);
  }

  setZero(val) {
    return this.set(masks.Z, val);
  }

  setAuthenticatedData(val) {
    return this.set(masks.AD, val);
  }

  setCheckingDisabled(val) {
    return this.set(masks.CD, val);
  }

  setRcode(code) {
    this.bits |= code & 0x0f;
    return this;
  }

  response() {
    return (this.bits & masks.QR) !== 0;
  }

  opcode() {
    return (this.bits >>> 11) & 0x0f;
  }

  authoritative() {
    return (this.bits & masks.AA) !== 0;
  }

  truncated() {
    return (this.bits & masks.TC) !== 0;
  }

  recursionDesired() {
    return (this.bits & masks.RD) !== 0;
  }

  recursionAvailable() {
    return (this.bits & masks.RA) !== 0;
  }

  zero() {
    return (this.bits & masks.Z) !== 0;
  }

  authenticatedData() {
    return (this.bits & masks.AD) !== 0;
  }

  checkingDisabled() {
    return (this.bits & masks.CD) !== 0;
  }

  rcode() {
    return this.bits & 0x0f;
  }

  inspect() {
    return {
      id: this.id,
      bits: this.bits,
      qdcount: this.qdcount,
      ancount: this.ancount,
      nscount: this.nscount,
      arcount: this.arcount,
      response: this.response(),
      opcode: this.opcode(),
      authoritative: this.authoritative(),
      truncated: this.truncated(),
      recursionDesired: this.recursionDesired(),
      recursionAvailable: this.recursionAvailable(),
      zero: this.zero(),
      authenticatedData: this.authenticatedData(),
      checkingDisabled: this.checkingDisabled(),
      rcode: this.rcode()
    };
  }
}


