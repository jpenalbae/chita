var r2pipe = require('./r2pipe');


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


exports.pattern = pattern;
exports.info = info;
