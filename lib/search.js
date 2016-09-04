'use strict';

const Long = require('long');
const misc = require('./misc');


const jump_opcodes = [ 'jmp #', 'call #', 'push #; ret' ];

const pivot32 = {
    opcodes: [ 'mov esp, #; ret', 'push #; pop esp; ret', 'xchg esp, #; ret' ],
    regs: [ 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp' ]
};

const pivot32compat = {
    opcodes: [ 'mov esp, #; ret', 'xchg esp, #; ret' ],
    regs: [ 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp' ]
};

const pivot64 = {
    opcodes: [ 'mov rsp, #; ret', 'push #; pop rsp; ret', 'xchg rsp, #; ret' ],
    regs: [ 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8',
            'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15' ]
};


function checkKeystone()
{
    let res = parseInt(r2.syscmd('rasm2 -L | grep "x86.ks" | wc -l'));

    if (res !== 1)
        console.error('This function might not work without keystone plugin installed');
}


function searchOpcode(reg, opcodes)
{
    opcodes.forEach(function(opcode) {
        opcode = opcode.replace('#', reg);
        let bytes = r2.cmd('"pa ' + opcode + '"').replace(/\n/g, '');

        if (bytes.length === 0)
            return;

        let res = r2.cmdj("/xj " + bytes);

        if (res.length > 0) {
            console.log('[*] ' + res.length + ' hits for opcode: ' + opcode + '');

            res.forEach(function(hit) {
                let addr = Long.fromNumber(hit.offset);
                let info = r2.cmd('?w ' + hit.offset).replace('\n', '');
                console.log('  - 0x' + misc.longToHex(addr) + ': ' + info);
            });

            console.log('');
        }
    });
}

function pivots()
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
            searchOpcode(reg, entry.opcodes);
        });
    });

}

function jumps(reg)
{
    if (!reg || (reg.length === 0)) {
        console.error('Missing register parameter');
        return;
    }

    checkKeystone();

    r2.cmd('e search.in=io.sections.exec');

    searchOpcode(reg, jump_opcodes);
}


exports.jumps = jumps;
exports.pivots = pivots;