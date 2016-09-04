'use strict';

const fs = require('fs');
const Long = require("long");


const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Cheap pattern generator using pseudorandom data, so it might not always
 * generate unique patterns
 *
 * @param  {int} len  Lenght of the pattern to be generated
 */
function pattern(len) {
    let result = '';
    for (let i = len; i > 0; --i)
        result += chars[Math.round(Math.random() * (chars.length - 1))];
    console.log(result);
}


/**
 * Concatenates two strings padding with spaces till the desired offset
 *
 * @param  {string} orig    Original string
 * @param  {string} append  String to append
 * @param  {int}    offset  Offset to append the string at
 *
 * @return {string} Returns the resulting string
 */
function concatAt(orig, append, offset) {
    let newline = orig;

    for (let x = orig.length; x<offset+1; x++)
        newline += ' ';

    newline += append;
    return newline;
}


function printInfo (info) {

    let line;

    /* Print general info header */
    line = 'CLASS'
    line = concatAt(line, 'OS', 10);
    line = concatAt(line, 'ARCH', 20);
    line = concatAt(line, 'BITS', 30);
    line = concatAt(line, 'ENDIAN', 40);
    line = concatAt(line, 'TYPE', 50);
    console.log(line.bold);

    /* Print general info data */
    line = info.bin.class;
    line = concatAt(line, info.bin.os, 10);
    line = concatAt(line, info.bin.arch, 20);
    line = concatAt(line, info.bin.bits, 30);
    line = concatAt(line, info.bin.endian, 40);
    line = concatAt(line, info.core.type, 50);
    console.log(line + '\n');



    /* Print protections header */
    line = 'ASLR';
    line = concatAt(line, 'NX', 10);
    line = concatAt(line, 'CANARY', 20);
    line = concatAt(line, 'PIE/PIC', 30);
    line = concatAt(line, 'RELRW', 40);
    line = concatAt(line, 'CRYPTO', 50);
    console.log(line.bold);

    /* Print protections data */
    line = info.bin.va.toString();
    line = concatAt(line, info.bin.nx.toString(), 10);
    line = concatAt(line, info.bin.canary.toString(), 20);
    line = concatAt(line, info.bin.pic.toString(), 30);
    line = concatAt(line, info.bin.relocs.toString(), 40);
    line = concatAt(line, info.bin.crypto.toString(), 50);
    console.log(line + '\n');
}


function roundUp(num, multiple)
{
    let remainder = num % multiple;

    if (remainder === 0)
        return num;

    return num + multiple - remainder;
}

function bufferRoundUp(hexstring, bytes)
{
    let tmpbuff, padding;

    hexstring = hexstring.replace("0x", "");
    if ((hexstring.length) % 2 !== 0)
        hexstring = '0' + hexstring;

    tmpbuff = Buffer.from(hexstring, 'hex');

    padding = bytes - (tmpbuff.length % bytes);
    if (padding === bytes)
        padding = 0;

    return Buffer.concat([Buffer.alloc(padding), tmpbuff]);
}


function hexToLittle(hexstring)
{
    let buf, res;
    let bytes = r2bin.bits / 8;

    hexstring = hexstring.replace("0x", "");
    buf = bufferRoundUp(hexstring, bytes);
    res = Buffer.alloc(buf.length);

    for (let x=0; x<res.length; x+=bytes) {
        if (bytes === 4) {
            res.writeUInt32LE(buf.readUInt32BE(x), x);
        } else if (bytes === 8) {
            res.writeUInt32LE(buf.readUInt32BE(x), x+4);
            res.writeUInt32LE(buf.readUInt32BE(x+4), x);
        }
    }

    return res.toString('hex');
}


function longToHex(value)
{
    let res = '';

    if (value.high !== 0)
        res = value.getHighBitsUnsigned().toString(16);

    res += value.getLowBitsUnsigned().toString(16);

    return res;
}

function longToHexLittle(value)
{
    return hexToLittle(longToHex(value));
}

function longToHexLittleEscaped(value)
{
    let res = longToHexLittle(value).replace(/(.{2})/g, "$1\\x");
    return '\\x' + res.replace(/\\x$/, '');
}



// function toLittlePrint(addr)
// {

//     var little = "";

//     /* Remove leading 0x */
//     addr = addr.replace("0x", "");

//     for (var x=addr.length; x>0; x-=2)
//         little += '\\x' + addr.substring(x-2, x);

//     return little;

// }



//exports.toLittlePrint = toLittlePrint;

exports.pattern = pattern;
exports.printInfo = printInfo;
exports.longToHexLittle = longToHexLittle;
exports.longToHex = longToHex;
exports.hexToLittle = hexToLittle;
exports.longToHexLittleEscaped = longToHexLittleEscaped;
exports.bufferRoundUp = bufferRoundUp;
