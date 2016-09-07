'use strict';

const fs = require('fs');
const Long = require('long');
const misc = require('./misc');


function parseRopChainJSON(json)
{
    let chain = [];

    json.ropchain.forEach(function(entry) {
        let gadget = {
            addr: entry.hexoffset,
            comment: entry.opcodes
        };

        if (entry.comment)
            gadget.comment += ' /* ' + entry.comment + ' */';

        chain.push(gadget);
    });


    return chain;
}

function parseRopChain(file)
{
    let chain = [];
    let text;

    text = fs.readFileSync(file);

    /* Try to parse rarop format */
    try {
        let json = JSON.parse(text.toString());
        return parseRopChainJSON(json);
    } catch (e) {};

    text = text.toString().split('\n');

    for (let x=0; x<text.length; x++) {
        let line = text[x].trim();
        line = line.replace('\t', ' ');
        line = line.replace(':', ' ');

        /* skip empty lines */
        if (line.length < 5)
            continue;

        let space = line.indexOf(' ');

        let addr = line.substring(0, space).trim().replace('0x', '');
        let comment = line.substring(space, line.length).trim();
        comment = comment.replace('#', '');
        comment = comment.replace(/\//g, '').trim();

        if (addr.length === 0) {
            addr = line;
            comment = '';
        }

        chain.push({ addr: addr, comment: comment });
    }

    return chain;

}

function ropToLang(file, lang)
{
    let format = (lang === 1024)? 'C' : lang;
    let chain = parseRopChain(file);
    let x;

    switch (format) {
        case 'C':
            console.log("unsigned char rop[] =");

            for (x=0; x<chain.length; x++) {
                let addr = Long.fromString(chain[x].addr, true, 16);
                console.log("    \"" + misc.longToHexLittleEscaped(addr) +
                    "\"    // " + chain[x].comment);
            }

            console.log(";");
            console.log('unsigned int rop_size = ' + (x * r2bin.bits / 8) + ';');
            break;

        case 'python':
            console.log("rop = bytearray(");

            for (x=0; x<chain.length; x++) {
                let addr = Long.fromString(chain[x].addr, true, 16);
                console.log("\t\"" + misc.longToHexLittleEscaped(addr) +
                    "\"\t# " + chain[x].comment);
            }

            console.log(")");
            console.log('rop_size = ' + (x * r2bin.bits / 8) + ';');

            break;

        case 'text':
            let result = '';
            for (x=0; x<chain.length; x++) {
                let addr = Long.fromString(chain[x].addr, true, 16);
                result += misc.longToHexLittleEscaped(addr);
            }
            console.log(result);
            break;


        default:
            console.log('Language output not supported');
            break;
    }

}

function findRet(file, callback)
{
    r2.cmd('e search.in=io.sections.exec');
    let results = r2.cmdj('/aj ret');

    return results[0].offset;
}


function dbgFileR2(chain, dest, ret) {

    let content = "";
    let width = r2bin.bits/8;

    /* Prepare the stack */
    for (let x=0; x<chain.length; x++) {
        let offset = (x*width).toString(16);
        content += 'wv' +  width + ' 0x' + chain[x].addr +
                    ' @ `dr?SP`+0x' + offset + '\n';
    }

    /* Set IP to some ret & continue */
    content += 'dr PC=0x' + ret.toString(16) + '\n';


    /* Display message */
    content += 'echo ---------------------------\n';
    content += 'echo - Your rop chain is ready -\n';
    content += 'echo ---------------------------\n';


    //console.log(content);
    fs.writeFileSync(dest, content);
    console.log('Debug file ready. To use it run: ');
    console.log('$ r2 -d -i ' + dest + ' binary_file');

    return 0;
}

function genDbgFile(input, output) {
    let chain = parseRopChain(input);
    let retoffset = findRet();

    dbgFileR2(chain, output, retoffset);
}


exports.genDbgFile = genDbgFile;
exports.ropToLang = ropToLang;
