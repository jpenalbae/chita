#!/usr/bin/env node

// TODO
//
// - ROP Gadgets
// - Search jumps and shit like that
// - Format strings helper
// - ROP chain debugger
// - Executable info
// - Stack pivots
// - offset

var mod_getopt = require('posix-getopt');

var misc = require('./lib/misc');
var rop = require('./lib/rop');


function usage () {
    console.error(
        '\n' +
        'Usage: node ' + process.argv[1] + ' command [parameters]\n\n' +
        'Where valid commands are:\n' +
        '  - pattern  Generate a pseudorandom text pattern\n' +
        '  - rop      Search for rop gadgets\n' +
        '  - rdbg     Generate a gdb or radare file to debug a ROP chain\n' +
        '  - fmt      Format string exploiting helper\n' +
        '  - jmp      Search for instructions such as \'jmp esp\' and so on\n' +
        '  - pivots   Search for stack pivots\n' +
        '  - offset   Calculate distance between two addresses\n' +
        '  - info     Show executable info\n\n'
        );
    process.exit(1);
}



/* Comnand parameters */
var _opts = {
    len: 1024,
    file: '',
    base: '0x0',
    onlyRet: true
};



/* Get the command and remove it */
var cmd = process.argv[2];
process.argv.splice(2, 1);
process.argc = process.argv.length;


/* Arguments parsing */
parser = new mod_getopt.BasicParser('l:f:b:ah', process.argv);
while ((option = parser.getopt()) !== undefined) {
    switch (option.option) {
    case 'l':
        _opts.len = parseInt(option.optarg);
        break;

    case 'f':
        _opts.file = option.optarg;
        break;

    case 'b':
        _opts.base = option.optarg;
        break;

    case 'a':
        _opts.onlyRet = false;
        break;

    case 'h':
        usage();
        break;

    default:
        usage();
        break;
    }
}

/* Check for unparsed args */
if (parser.optind() < process.argv.length) {
    console.error('Invalid argument: ' + process.argv[parser.optind()] + '\n');
    usage();
}
    


/* Command parsing */
switch (cmd) {
    case 'pattern':
        misc.pattern(_opts.len);
        break;

    case 'rop':
        rop.gadgets(_opts.file, _opts.onlyRet, _opts.base);
        break;

    case 'info':
        misc.info(_opts.file);
        break;

    case 'rdbg':
        break;

    case 'fmt':
        break;

    case 'jmp':
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
