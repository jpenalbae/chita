#!/usr/bin/env node
'use strict';

// TODO
//
// - Search jumps and shit like that
// - ROP chain debugger
// - ROP output for C/Python/js
// - Stack pivots


const r2pipe = require('r2pipe');
const fs = require('fs');
const mod_getopt = require('posix-getopt');

const misc = require('./lib/misc');
const fmt = require('./lib/fmt');
const rop = require('./lib/rop');
const search = require('./lib/search');




/* Globals */
global.r2 = null;
global.r2bin = {};

const help = {};


/* Comnand parameters */
const _opts = {
    len: 1024,
    file: '',
    chain: '',
    base: '0x0',
    written: 0,
    onlyRet: true
};

help.info = function () {
    console.error(
        '\n' +
        'Prints useful exploitation info for the loaded binary\n' +
        'Usage: #!pipe chita info\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita info\n\n'
    );

    process.exit(1);
};

help.pattern = function () {
    console.error(
        '\n' +
        'Prints a random pattern which could be useful to find memory locations\n' +
        'Usage: #!pipe chita pattern [-l len]\n\n' +

        'Options:\n' +
        '   -l len: length of the pattern\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita pattern -l 1024\n\n'
    );

    process.exit(1);
};

help.fmt = function () {
    console.error(
        '\n' +
        'Format string exploitation helper\n' +
        'Usage: #!pipe chita fmt -p pos (-a addr -d data) | -f file [-w written]\n\n' +

        'Options:\n' +
        '  -p pos:     The position of the fmt string in the stack\n' +
        '  -a addr:    Destination addr to write at\n' +
        '  -d data:    Data we want to write (hexstring)\n' +
        '  -f file:    File with addr/data pairs (used for multiple writes)\n' +
        '  -w written: Number of bytes already written by the fmt string (default 0)\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita fmt -p 7 -a 0x0804a018 -d 0x41414141\n' +
        '  [0x00000000]> #!pipe chita fmt -p 7 -f /tmp/fmt.writes\n\n' +

        'Multiple writes file format example (to use with -f):\n' +
        '  0x0804a140 0x41414141\n' +
        '  0x0804a150 42424242\n' +
        '  0x0804a160 4343434343434343\n\n'
    );

    process.exit(1);
};

help.rop2c = function () {
    console.error(
        '\n' +
        'Generate C/python code from ropchain file\n' +
        'Usage: #!pipe chita rop2c -r ropfile [-l lang]\n\n' +
        'Options:\n' +
        '  -r ropfile:  The file containing the rop gadgets file\n' +
        '  -w lang:     Supported output languages: C, python (default C)\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita rop2c -r /tmp/gadgets\n' +
        '  [0x00000000]> #!pipe chita rop2c -r /tmp/gadgets -l python\n\n' +

        'ROP gadgets file format (to use with -r):\n' +
        '  0x08048504: les ecx, [eax]; pop ebx; ret;\n' +
        '  080485de:   inc ecx; ret;\n' +
        '  0x080484e7  pop edi; pop ebx; ret;\n' +
        '  0xAAAAAAA   // pop data\n' +
        '  0xBB        pop data\n\n'
    );

    process.exit(1);
};


help.rdbg = function () {
    console.error(
        '\n' +
        'Generate r2 cmds file from a rop chain file in order to debug it.\n' +
        'Usage: #!pipe chita rdbg -r ropfile -o outfile\n\n' +
        'Options:\n' +
        '  -r ropfile:  The file containing the rop gadgets file\n' +
        '  -o outfile:  The file to write the output to\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita rdbg -r /tmp/gadgets -o /tmp/rop.r2\n' +
        '  $ r2 -d -i /tmp/rop.r2 bin_file\n\n' +

        'ROP gadgets file format (to use with -r):\n' +
        '  0x08048504: les ecx, [eax]; pop ebx; ret;\n' +
        '  080485de:   inc ecx; ret;\n' +
        '  0x080484e7  pop edi; pop ebx; ret;\n' +
        '  0xAAAAAAA   // pop data\n' +
        '  0xBB        pop data\n\n'
    );

    process.exit(1);
};

help.jmp = function () {
    console.error(
        '\n' +
        'Find jumps to the given register.\n' +
        'Usage: #!pipe chita jmp -r register\n\n' +
        'Options:\n' +
        '  -r register:  The register to jump to\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita jmp -r rsp\n\n'
    );

    process.exit(1);
};

help.pivot = function () {
    console.error(
        '\n' +
        'Search for ROP stack pivots.\n' +
        'Usage: #!pipe chita pivot\n\n' +

        'Examples:\n' +
        '  [0x00000000]> #!pipe chita pivot\n\n'
    );

    process.exit(1);
};


function usage () {
    console.error(
        '\n' +
        'Usage: #!pipe chita command [options]\n\n' +
        'Where valid commands are:\n' +
        '  pattern  Generate a pseudorandom text pattern\n' +
        '  rdbg     Generate a gdb or radare file to debug a ROP chain\n' +
        '  rop2c    Generate C/python code from ROP chain file\n' +
        '  fmt      Format string exploiting helper\n' +
        '  jmp      Search for instructions such as \'jmp esp\' and so on\n' +
        '  pivot    Search for stack pivots\n' +
        '  info     Show executable info\n' +
        '  help     Shows this help\n\n' +
        'Extended help: #!pipe chita [command] -h\n\n'
        );
    process.exit(1);
}


function doFmtString() {
    let writes = [];

    if (r2bin.endian !== 'little') {
        console.log('Format strings helper only works with little endian');
        return;
    }

    if (!_opts.pos) {
        console.error('Format string position is mandatory');
        process.exit(1);
    }

    /* Writes by command line */
    if (_opts.addr && _opts.data) {
        writes = [{
            addr: _opts.addr,
            data: _opts.data
        }];

    /* Writes by file */
    } else if (_opts.file) {
        let file = fs.readFileSync(_opts.file).toString();
        let lines = file.split('\n');
        lines.forEach(function(line) {
            line = line.trim().replace('\t', ' ');
            line = line.replace(':', ' ');
            //console.log(line);

            if (line.length < 1)
                return;

            let fields = line.split(' ');
            fields[1] = line.substr(fields[0].length);

            let entry = {
                addr: fields[0].trim(),
                data: fields[1].trim()
            };

            //console.log(entry);
            writes.push(entry);
        });

    /* Bad args */
    } else {
        console.error('Bad arguments');
        process.exit(1);
    }

    //console.log(writes);
    fmt.genFmt(_opts.pos, writes, _opts.written);
}



/* Get the command and remove it */
var cmd = process.argv[2];
process.argv.splice(2, 1);
process.argc = process.argv.length;


/* Arguments parsing */
let option;
const parser = new mod_getopt.BasicParser('l:f:b:r:d:a:p:w:o:h', process.argv);
while ((option = parser.getopt()) !== undefined) {
    switch (option.option) {
    case 'l':
        _opts.len = option.optarg;
        break;

    case 'f':
        _opts.file = option.optarg;
        break;

    case 'r':
        _opts.chain = option.optarg;
        break;

    case 'b':
        _opts.base = option.optarg;
        break;

    case 'a':
        _opts.addr = option.optarg;
        break;

    case 'd':
        _opts.data = option.optarg;
        break;

    case 'o':
        _opts.output = option.optarg;
        break;

    case 'p':
        _opts.pos = option.optarg;
        break;

    case 'w':
        _opts.written = parseInt(option.optarg);
        break;

    default:
        if (typeof help[cmd] === 'function')
            help[cmd]();
        else
            usage();

        break;
    }
}

/* Check for unparsed args */
if (parser.optind() < process.argv.length) {
    console.error('Invalid argument: ' + process.argv[parser.optind()] + '\n');
    usage();
}


/* Initialize r2 data */
r2 = r2pipe.lpipeSync();
if (!process.env.R2PIPE_OUT && !process.env.R2PIPE_IN) {
    console.log('This script must be executed inside an r2 session');
    return 1;
}

/* Get bin info */
let info = r2.cmdj('ij');
r2bin.arch = info.bin.arch;
r2bin.bits = info.bin.bits;
r2bin.endian = info.bin.endian;

//fmt.test();

/* Command parsing */
switch (cmd) {
    case 'pattern':
        misc.pattern(parseInt(_opts.len));
        break;

    // case 'rop':
    //     rop.gadgets(_opts.file, _opts.onlyRet, _opts.base);
    //     break;

    case 'info':
        misc.printInfo(info);
        break;

    case 'rdbg':
        rop.genDbgFile(_opts.chain, _opts.output);
        break;

    case 'rop2c':
        rop.ropToLang(_opts.chain, _opts.len);
        break;

    case 'fmt':
        doFmtString();
        break;

    case 'jmp':
        search.jumps(_opts.chain);
        break;

    case 'pivot':
        search.pivots();
        break;

    case 'help':
        usage();
        break;

    default:
        console.error('Invalid command: ' + cmd);
        usage();
        break;
}


//process.exit(0);
