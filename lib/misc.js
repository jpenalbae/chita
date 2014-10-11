var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Cheap pattern generator using pseudorandom data, so it might not always
 * generate unique patterns
 * 
 * @param  {int} len  Lenght of the pattern to be generated
 * @return {string}   The generated pattern
 */
function pattern(len) {
    var result = '';
    for (var i = len; i > 0; --i) 
        result += chars[Math.round(Math.random() * (chars.length - 1))];
    return result;
}


exports.pattern = pattern;
