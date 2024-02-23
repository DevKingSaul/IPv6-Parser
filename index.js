const CIDR_BLOCK_REGEX_6 = /^([A-Fa-f0-9.:]*)\/(\d{1,3})$/;
const CIDR_BLOCK_REGEX_4 = /^([0-9.]*)\/(\d{1,2})$/;
const IPv4_MASK = Buffer.from("00000000000000000000FFFF", "hex");

const UINT_128_LIMIT = 0xffffffffffffffffffffffffffffffffn;

function parseIPv4(IPv4) {
    let IPSegments = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(IPv4)
    if (!IPSegments) return null
  
    IPSegments = IPSegments.slice(1, 5).map( byte => Number(byte) )
  
    if (IPSegments.some( byte => byte > 255 )) return null
  
    return Buffer.from(IPSegments)
}
  
function parseIPv6(IPv6) {
    const buffer = Buffer.alloc(16)
  
    let currentSegment = ""
    let truncatePos = null
  
    const segments = []
  
    for (let pos = 0; pos <= IPv6.length; pos++) {
        const char = IPv6[pos]
  
        if (char === ':' || pos === IPv6.length) {
            if (currentSegment.length >= 7) {
                // Dotted-quad notation

                let IPv4Segments = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(currentSegment)

                if (!IPv4Segments)
                    throw Error("Bad IPv4 Segment");

                IPv4Segments = IPv4Segments.slice(1, 5).map( byte => Number(byte).toString(16) )

                if (IPv4Segments.some( byte => byte.length > 2 )) throw Error("Bad IPv4 Segment")

                segments.push(IPv4Segments.slice(0, 2).join(''))
                segments.push(IPv4Segments.slice(2, 4).join(''))

                currentSegment = ""
            } else if (currentSegment.length > 0) {
                // IPv6 Segment (1 to 4 Hexadeimal Digits)

                if (!/^[A-Fa-f0-9]{1,4}$/.test(currentSegment)) throw Error("Bad IPv6 Segment")

                segments.push(('0000' + currentSegment).slice(-4))
                currentSegment = ""
            }
  
            if (IPv6[pos + 1] === ':') {
                if (truncatePos !== null)
                    throw Error("Multiple truncate delimiters");

                pos++;
                truncatePos = segments.length
            }
      } else {
        currentSegment += char
      }
    }
  
    if (segments.length > 8)
        throw Error("Excessive segments");
  
    if (truncatePos === null && segments.length !== 8)
        throw Error("Lacks sufficent segments");
  
    const zeroPad = 8 - segments.length
  
    if (zeroPad > 0) {
      const prefix = segments.slice(0, truncatePos).join('')
      const suffix = segments.slice(truncatePos).join('')
  
      buffer.write(prefix, 'hex')
      buffer.write(suffix, (truncatePos + zeroPad) * 2, 'hex')
    } else {
      buffer.write(segments.join(''), 'hex')
    }
  
    return buffer
}

function CheckBufferZero(buf) {
    for (const byte of buf) {
        if (byte !== 0) return false;
    }
    return true;
}

class IPv4Block {
    constructor(blockStr) {
        const regexResult = CIDR_BLOCK_REGEX_4.exec(blockStr);
        if (!regexResult) throw Error("Invalid CIDR Notation.");

        const maskBits = parseInt(regexResult[2]);
        if (maskBits > 32) throw Error("Illegal Amount of Bits.");

        this.rawAddress = parseIPv4(regexResult[1]).readUInt32BE();
        this.maskBits = maskBits;
        this.mask = (0xffffffff << (32 - this.maskBits)) & 0xffffffff; // Generate MSB Bitmask

        // Make Mask Unsigned
        this.mask = this.mask >>> 0;

        const leftMask = 0xffffffff >>> this.maskBits;

        if ((this.rawAddress & leftMask) != 0) throw Error("Values exceed Subnet Mask");
    }

    equals(ipv4) {
        if (((ipv4.readUInt32BE() & this.mask) >>> 0) !== this.rawAddress) return false;

        return true;
    }
}

class IPv6Block {
    constructor(blockStr) {
        const regexResult = CIDR_BLOCK_REGEX_6.exec(blockStr);
        if (!regexResult) throw Error("Invalid CIDR Notation.");

        const maskBits = parseInt(regexResult[2]);
        if (maskBits > 128) throw Error("Illegal Amount of Bits.");

        this.rawAddress = parseIPv6(regexResult[1]);
        this.maskBytes = maskBits >> 3; // Optimization of maskBits / 8
        this.maskBits = maskBits & 7; // Optimization of maskBits % 8
        this.mask = (0xff << (8 - this.maskBits)) & 0xff; // Generate MSB Bitmask

        this.preamble = this.rawAddress.subarray(0, this.maskBytes);
        this.partialByte = this.mask !== 0 ? this.rawAddress[this.maskBytes] & this.mask : 0;

        if (this.maskBits !== 0) {
            const leftMask = 0xff >> this.maskBits;

            if ((this.rawAddress[this.maskBytes] & leftMask) != 0) throw Error("Values exceed Subnet Mask");
            if (!CheckBufferZero(this.rawAddress.subarray(this.maskBytes + 1))) throw Error("Values exceed Subnet Mask");
        } else {
            if (!CheckBufferZero(this.rawAddress.subarray(this.maskBytes))) throw Error("Values exceed Subnet Mask");
        }
    }

    equals(ipv6) {
        if (!this.preamble.equals(ipv6.subarray(0, this.maskBytes))) return false;
        if (this.mask !== 0 && this.partialByte !== (ipv6[this.maskBytes] & this.mask)) return false;

        return true;
    }
}

module.exports = {
    parseIPv4,
    parseIPv6,
    IPv6Block,
    IPv4Block
}