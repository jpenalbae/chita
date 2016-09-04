'use strict';

const Long = require('long');
const misc = require('./misc');


const jump_opcodes = [ 'jmp #', 'call #' ];
const jump_opcodes_ret = [ 'push #' ];

const pivot32 = {
    opcodes: [ 'mov esp, #', 'push #; pop esp', 'xchg esp, #' ],
    regs: [ 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp' ]
};

const pivot32compat = {
    opcodes: [ 'mov esp, #', 'xchg esp, #' ],
    regs: [ 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp' ]
};

const pivot64 = {
    opcodes: [ 'mov rsp, #', 'push #; pop rsp', 'xchg rsp, #' ],
    regs: [ 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8',
            'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15' ]
};


function checkKeystone()
{
    let res = parseInt(r2.syscmd('rasm2 -L | grep "x86.ks" | wc -l'));

    if (res !== 1)
        console.error('This function might not work without keystone plugin installed');
}


function searchOpcode(reg, opcodes, extended, append)
{
    opcodes.forEach(function(opcode) {
        opcode = opcode.replace('#', reg);
        let bytes = r2.cmd('"pa ' + opcode + '"').replace(/\n/g, '');

        if (bytes.length === 0)
            return;

        if (append)
            bytes += append;

        let res = r2.cmdj("/xj " + bytes);

        if (res.length > 0) {
            let dupes = [];
            console.log('[*] hits for opcode: ' + opcode + '');

            res.forEach(function(hit) {

                /* Workaround for fupes */
                if (dupes.indexOf(hit.offset) !== -1)
                    return;
                dupes.push(hit.offset);

                let addr = Long.fromNumber(hit.offset);
                let info = r2.cmd('?w ' + hit.offset).replace('\n', '');
                let output = '  - 0x' + misc.longToHex(addr) + ': ' + info;

                if (extended) {
                    let tmp = r2.cmdj('pdj 3 @ ' + hit.offset);
                    let disas = ([tmp[0].opcode, tmp[1].opcode, tmp[2].opcode]).join('; ');
                    output += ' - (' + disas + ')';
                }

                console.log(output);
            });

            console.log('');
        }
    });
}

function pivots(extended)
{
    let check = [];

    checkKeystone();
    r2.cmd('e search.in=io.sections.exec');

    if (r2bin.bits === 64) {
        check.push(pivot64);
        check.push(pivot32compat);
    } else {
        check.push(pivot32);
    }

    check.forEach(function(entry) {
        entry.regs.forEach(function(reg) {
            searchOpcode(reg, entry.opcodes, extended, 'C3'); // RET
            if (everyRet)
                searchOpcode(reg, entry.opcodes, extended, 'C2'); // RET imm16

            //searchOpcode(reg, entry.opcodes, extended, 'CB'); // RETF
            //searchOpcode(reg, entry.opcodes, extended, 'CA'); // RETF imm16
        });
    });

}

function jumps(reg, extended)
{
    if (!reg || (reg.length === 0)) {
        console.error('Missing register parameter');
        return;
    }

    checkKeystone();

    r2.cmd('e search.in=io.sections.exec');

    searchOpcode(reg, jump_opcodes, extended);
    searchOpcode(reg, jump_opcodes_ret, extended, 'C3'); // RET
    if (everyRet)
        searchOpcode(reg, jump_opcodes_ret, extended, 'C2'); // RET imm16

    //searchOpcode(reg, jump_opcodes, extended, 'CB'); // RETF
    //searchOpcode(reg, jump_opcodes, extended, 'CA'); // RETF imm16
}


exports.jumps = jumps;
exports.pivots = pivots;