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

                IPv4Segments = IPv4Segments.slice(1, 5).map( byte => Number(byte).toString(16).padStart(2, "0") )

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

// TODO: Make these into Minimum and Maximum, as its proven to be much more performant.

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

    _equals(u32) {
        if (((u32 & this.mask) >>> 0) !== this.rawAddress) return false;

        return true;
    }

    equals(ipv4) {
        return this._equals(ipv4.readUInt32BE());
    }
}

class IPv6Block {
    constructor(blockStr) {
        const regexResult = CIDR_BLOCK_REGEX_6.exec(blockStr);
        if (!regexResult) throw Error("Invalid CIDR Notation.");

        const maskBits = BigInt(regexResult[2]);
        if (maskBits > 128n) throw Error("Illegal Amount of Bits.");

        const rawAddress = parseIPv6(regexResult[1]);
        this.upperHigh_Addr = rawAddress.readUInt32BE();
        this.upperLow_Addr = rawAddress.readUInt32BE(4);
        this.lowerHigh_Addr = rawAddress.readUInt32BE(8);
        this.lowerLow_Addr = rawAddress.readUInt32BE(12);

        const MaskBigInt = (UINT_128_LIMIT << (128n - maskBits)) & UINT_128_LIMIT; // Generate MSB Bitmask

        this.upperHigh_Mask = Number((MaskBigInt >> 96n) & 0xffffffffn);
        this.upperLow_Mask = Number((MaskBigInt >> 64n) & 0xffffffffn);
        this.lowerHigh_Mask = Number((MaskBigInt >> 32n) & 0xffffffffn);
        this.lowerLow_Mask = Number(MaskBigInt & 0xffffffffn);

        const LeftMaskBigInt = UINT_128_LIMIT >> maskBits;

        const upperHigh_LeftMask = Number((LeftMaskBigInt >> 96n) & 0xffffffffn);
        const upperLow_LeftMask = Number((LeftMaskBigInt >> 64n) & 0xffffffffn);
        const lowerHigh_LeftMask = Number((LeftMaskBigInt >> 32n) & 0xffffffffn);
        const lowerLow_LeftMask = Number(LeftMaskBigInt & 0xffffffffn);

        if ((this.upperHigh_Addr & upperHigh_LeftMask) != 0) throw Error("Values exceed Subnet Mask");
        if ((this.upperLow_Addr & upperLow_LeftMask) != 0) throw Error("Values exceed Subnet Mask");
        if ((this.lowerHigh_Addr & lowerHigh_LeftMask) != 0) throw Error("Values exceed Subnet Mask");
        if ((this.lowerLow_Addr & lowerLow_LeftMask) != 0) throw Error("Values exceed Subnet Mask");
    }

    _equals(upperHigh, upperLow, lowerHigh, lowerLow) {
        if (((upperHigh & this.upperHigh_Mask) >>> 0) !== this.upperHigh_Addr) return false;
        if (((upperLow & this.upperLow_Mask) >>> 0) !== this.upperLow_Addr) return false;
        if (((lowerHigh & this.lowerHigh_Mask) >>> 0) !== this.lowerHigh_Addr) return false;
        if (((lowerLow & this.lowerLow_Mask) >>> 0) !== this.lowerLow_Addr) return false;

        return true;
    }

    equals(ipv6) {
        return this._equals(
            ipv6.readUInt32BE(),
            ipv6.readUInt32BE(4),
            ipv6.readUInt32BE(8),
            ipv6.readUInt32BE(12)
        );
    }
}

const RFC_791 = new IPv4Block("0.0.0.0/8");
const RFC_6598 = new IPv4Block("100.64.0.0/10");
const RFC_1122 = new IPv4Block("127.0.0.0/8"); // Local Allowed
const RFC_3927 = new IPv4Block("169.254.0.0/16"); // Local Allowed
const RFC_1918_1 = new IPv4Block("10.0.0.0/8"); // Local Allowed
const RFC_1918_2 = new IPv4Block("172.16.0.0/12"); // Local Allowed
const RFC_1918_3 = new IPv4Block("192.168.0.0/16"); // Local Allowed
const RFC_6890 = new IPv4Block("192.0.0.0/24");
const RFC_7526 = new IPv4Block("192.88.99.0/24");
const RFC_2544 = new IPv4Block("198.18.0.0/15");
const RFC_5737_1 = new IPv4Block("192.0.2.0/24");
const RFC_5737_2 = new IPv4Block("198.51.100.0/24");
const RFC_5737_3 = new IPv4Block("203.0.113.0/24");
const RFC_1112 = new IPv4Block("224.0.0.0/3");
const RFC_7535 = new IPv4Block("192.31.196.0/24");
const RFC_7450 = new IPv4Block("192.52.193.0/24");
const RFC_7534_IP4 = new IPv4Block("192.175.48.0/24");

function ValidateIPv4(uint32, allowLocal) {
    if (RFC_791._equals(uint32)) return false;
    if (RFC_6598._equals(uint32)) return false;
    if (RFC_6890._equals(uint32)) return false;
    if (RFC_7526._equals(uint32)) return false;
    if (RFC_2544._equals(uint32)) return false;
    if (RFC_5737_1._equals(uint32)) return false;
    if (RFC_5737_2._equals(uint32)) return false;
    if (RFC_5737_3._equals(uint32)) return false;
    if (RFC_1112._equals(uint32)) return false;
    if (RFC_7535._equals(uint32)) return false;
    if (RFC_7450._equals(uint32)) return false;
    if (RFC_7534_IP4._equals(uint32)) return false;

    if (!allowLocal) {
        if (RFC_1122._equals(uint32)) return false;
        if (RFC_3927._equals(uint32)) return false;
        if (RFC_1918_1._equals(uint32)) return false;
        if (RFC_1918_2._equals(uint32)) return false;
        if (RFC_1918_3._equals(uint32)) return false;
    }

    return true;
}

const RFC_2928 = new IPv6Block("2001::/23");
const RFC_3056 = new IPv6Block("2002::/16");
const RFC_3849 = new IPv6Block("2001:db8::/32");
const RFC_4193 = new IPv6Block("fc00::/7");
const RFC_4291_1 = new IPv6Block("fe80::/10");
const RFC_4291_2 = 1;
const RFC_4291_3 = 0;
const RFC_6052 = new IPv6Block("64:ff9b::/96");
const RFC_6666 = new IPv6Block("100::/64");
const RFC_7534_IP6 = new IPv6Block("2620:4f:8000::/48");
const RFC_8215 = new IPv6Block("64:ff9b:1::/48");
const MULTICAST_IP6 = new IPv6Block("ff00::/8");

function ValidateIPv6(upperHigh, upperLow, lowerHigh, lowerLow, allowLocal) {
    if (RFC_2928._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (RFC_3056._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (RFC_3849._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (upperHigh == 0 && upperLow == 0 && lowerHigh == 0 && lowerLow == RFC_4291_3) return false;
    if (RFC_6052._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (RFC_6666._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (RFC_7534_IP6._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (RFC_8215._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    if (MULTICAST_IP6._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;

    if (!allowLocal) {
        if (RFC_4193._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
        if (upperHigh == 0 && upperLow == 0 && lowerHigh == 0 && lowerLow == RFC_4291_2) return false;
        if (RFC_4291_1._equals(upperHigh, upperLow, lowerHigh, lowerLow)) return false;
    }

    return true;
}

function Validate(ip, allowLocal = false) {
    const upperHigh = ip.readUInt32BE();
    const upperLow = ip.readUInt32BE(4);
    const lowerHigh = ip.readUInt32BE(8);
    const lowerLow = ip.readUInt32BE(12);
    if (upperHigh == 0 && upperLow == 0 && lowerHigh == 0xffff) {
        return ValidateIPv4(lowerLow, allowLocal);
    } else {
        return ValidateIPv6(upperHigh, upperLow, lowerHigh, lowerLow, allowLocal);
    }
}

module.exports = {
    parseIPv4,
    parseIPv6,
    IPv6Block,
    IPv4Block,
    ValidateIPv4,
    ValidateIPv6,
    Validate
}