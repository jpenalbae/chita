var r2pipe = require('r2pipe');
var fs = require('fs');


var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Cheap pattern generator using pseudorandom data, so it might not always
 * generate unique patterns
 * 
 * @param  {int} len  Lenght of the pattern to be generated
 */
function pattern(len) {
    var result = '';
    for (var i = len; i > 0; --i) 
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
    var newline = orig;

    for (var x = orig.length; x<offset+1; x++)
        newline += ' ';

    newline += append;
    return newline;
}


function printInfo (info) {

    var line;

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

/**
 * Displays useful binary information for explotitation using radare
 * 
 * @param  {string} file  Path to the file to extract info from
 */
function info(file) {
    r2pipe.pipe(file, function (r2) {
        r2.cmd('ij', function (res) {
            try {
                var info = JSON.parse(res);
                printInfo(info);
            } catch (e) {
                console.error(e);
            } finally {
                r2.quit();
            }
        });
    });
}




function toLittlePrint(addr)
{

    var little = "";

    /* Remove leading 0x */
    addr = addr.replace("0x", "");

    for (var x=addr.length; x>0; x-=2)
        little += '\\x' + addr.substring(x-2, x);

    return little;

}


function parseRopChain(file) 
{
    var chain = [];

    text = fs.readFileSync(file);
    text = text.toString().split('\n');

    for (var x=0; x<text.length; x++) {
        var line = text[x].trim();
        line = line.replace('\t', ' ');

        /* skip empty lines */
        if (line.length < 5)
            continue;

        var space = line.indexOf(' ');

        var addr = line.substring(0, space).trim();
        var comment = line.substring(space, line.length).trim();

        chain.push({ addr: addr, comment: comment });
    }

    return chain;

}

function findRet(file, callback)
{
    r2pipe.pipe(file, function (r2) {
        r2.cmd('e search.in=io.sections.exec', function (res) {
            r2.cmdj('/aj ret', function (results) {
                callback(results[0].offset)
                r2.quit();
            });
        });
    });   
}


function dbgFileR2(chain, dest, ret) {

    var content = "";
    var width =  4;


    /* Prepare the stack */
    for (var x=0; x<chain.length; x++) {
        var offset = (x*width).toString(16);
        content += 'wv ' + chain[x].addr + ' @ `dr?sp`+0x' + offset + '\n';
    }

    /* Set IP to some ret & continue */
    content += 'dr pc=0x' + ret.toString(16) + '\n';

    /* Create step macro */
    content += '(step, ds, pd 1 @ `dr?pc`)\n';
    content += '$step=.(step)\n';

    /* Display message */
    content += 'echo ---------------------------\n';
    content += 'echo - Your rop chain is ready -\n';
    content += 'echo ---------------------------\n';


    fs.writeFileSync(dest, content);

    return 0;
}



exports.pattern = pattern;
exports.info = info;
exports.toLittlePrint = toLittlePrint;
exports.parseRopChain = parseRopChain;
exports.findRet = findRet;
exports.dbgFileR2 = dbgFileR2;
