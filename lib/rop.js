var r2pipe = require('./r2pipe');


function printGadgets(gadgets, onlyRet, base) {
    gadgets.forEach(function(gadget) {
        var len = gadget.opcodes.length;
        if ((gadget.opcodes[len-1].type !== 'ret') && onlyRet)
                return;

        var newbase = gadget.opcodes[0].offset + parseInt(base, 16);
        var line = '0x' + newbase.toString(16) + ' ';

        for (var x = 0; x < gadget.opcodes.length; x++) {
            line += gadget.opcodes[x].opcode + '; ';
        }

        console.log(line);
    });
}


function gadgets(file, onlyRet, base) {
    r2pipe.pipe(file, function (r2) {
        r2.cmd('/Rj', function (res) {
            try {
                var gadgets = JSON.parse(res);
                printGadgets(gadgets, onlyRet, base);
            } catch (e) {
                console.error(e);
            } finally {
                r2.quit();
            }
        });
    });
}

exports.gadgets = gadgets;
