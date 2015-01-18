var r2pipe = require('r2pipe');
var colors = require('colors');


function printGadgets(gadgets, onlyRet, base) {
    gadgets.forEach(function(gadget) {
        var len = gadget.opcodes.length;

        /* Ignore non ret gadgets */
        if ((gadget.opcodes[len-1].type !== 'ret') && onlyRet)
                return;

        /* Ignore only ret gadgets */
        if ((len === 1) && (gadget.opcodes[0].type === 'ret'))
            return;


        var newbase = gadget.opcodes[0].offset + parseInt(base, 16);
        var line = '0x' + newbase.toString(16) + '  ';
        line = line.bold;

        for (var x = 0; x < gadget.opcodes.length; x++) {
            line += gadget.opcodes[x].opcode + '; ';
        }

        console.log(line);
    });
}


function gadgets(file, onlyRet, base) {
    r2pipe.pipe(file, function (r2) {
        r2.cmd('e search.roplen=8', function (none) {
            r2.cmd('e search.in=io.sections.exec', function (none) {
                r2.cmd('/Rj', function (res) {
                    try {
                        var gadgets = JSON.parse(res);
                        printGadgets(gadgets, onlyRet, base);
                    } catch (e) {
                        console.error("Exception: " + e);
                    } finally {
                        r2.quit();
                    }
                });
            });
        });
    });
}

exports.gadgets = gadgets;
