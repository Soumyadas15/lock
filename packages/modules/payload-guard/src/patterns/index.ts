export const PATTERNS = {
  xss: [
    /<script\b[^>]*>[\s\S]*?<\/script\b[^>]*>/i,
    /<\s*script\s*>|\bon\w+\s*=|\balert\s*\(|javascript\s*:/i,
    /\bon(?:load|error|mouse|focus|blur|click|change|submit|pointer\w+|animation\w+)\s*=["']/i,
    /(?:%3C|<)(?:%2F|\/)*(?:%73|s)(?:%63|c)(?:%72|r)(?:%69|i)(?:%70|p)(?:%74|t)/i,
    /data:(?:text|application)\/(?:javascript|ecmascript|html|xml)/i,
    /data:.*?;base64,[A-Za-z0-9+/=]+/i,
    /(?:<[^>]*\s+|\s+)[oO][nN][a-zA-Z]+\s*=|\b(?:eval|setTimeout|setInterval|Function|execScript)\s*\(/i,
    /<(?:form|input)\b[^>]*\bid\s*=\s*["'](?:parentNode|proto|constructor|test)\b/i,
    /<(?:form|input)\b[^>]*\bid=[^>]*>(?:\s*<[^>]*\bname\s*=\s*["'](?:innerText|innerHTML|outerHTML)\b)/i,
    /<(?:svg|img|iframe|form|input|audio|video|link|embed|object)\b[^>]*\b(?:on\w+|src|data|href)\s*=/i,
    /<\w+[^>]*src\s*=\s*["']https?:\/\/[^"'>]+["']?(?![^>]*>)/i,
    /(?:javascript|data|vbscript|file):/i,
  ],

  sqli: [
    /(?:\b(?:union\b(?:.{0,20}\bselect\b|\ballselect\b)|select\b.{0,20}\bfrom\b|\bor\b.{0,20}(?:['"]?\d+['"]?).{0,20}=.{0,20}(?:['"]?\d+['"]?)|\bdrop\b.{0,20}\btable\b|\bexec\b.{0,20}\bxp_cmdshell\b|\binsert\b.{0,20}\binto\b|\bdelete\b.{0,20}\bfrom\b|\bupdate\b.{0,20}\bset\b)|'(?:\s*(?:--|#|\/\*)))/i,
    /(?:\b(?:--\s|#|\/\*)|\b(?:CONCAT|CHAR|SUBSTRING|ASCII|BENCHMARK|SLEEP|LOAD_FILE|EXTRACTVALUE|UPDATEXML)\s*\()/i,
    /(?:UNION[\s\/\*]+SELECT|SELECT[\s\/\*]+FROM|AND|OR)[\s\/\*]+\d+=/i,
    /'\s+(?:AND|OR)\s+(?:['"]?\d+['"]?)\s*(?:=|!=|<>|LIKE)\s*['"]?(?:['"]?\d+['"]?)'?/i,
    /;\s*(?:CREATE|ALTER|DROP|TRUNCATE|RENAME|INSERT|SELECT|UPDATE|DELETE|MERGE)\s+/i,
    /\b(?:SEL\s*E*\s*C\s*T|UNI\s*O*\s*N\s+SEL\s*E*\s*C\s*T)\b[\s\n\r\t]*.*?\b(?:FR\s*O*\s*M)\b/i,
  ],

  commandInjection: [
    /(?:\$\(|\`|\|\s*[\w\d\s\-\/\\]+\s*\||; \w+|\|\|\s*\w+|\&\&\s*\w+|(?<!\()\|\s*\w+)/i,
    /(?:\/bin\/(?:ba)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?|wget\s|curl\s|nc\s|ncat\s|telnet\s|lftp\s)/i,
    /\$\(.*?\)|\`.*?\`/i,
    /(?:;|\||\|\||&&)\s*(?:id|whoami|cat|echo|rm|touch|chmod|chown|wget|curl|bash|sh|python|perl|ruby|php)/i,
    /\benv\b|\bset\b|\bexport\b|\bPATH=/i,
    /\u202E|\u202D|\u061C|\u2066|\u2067|\u2068|\u202B|\u202C|\u2069/,
    /\beval\s*\(|\bFunction\s*\(|\bexec\s*\(|\bsetTimeout\s*\(|\bsetInterval\s*\(/i,
  ],

  pathTraversal: [
    /(?:\.\.\/|\.\.\\|\.\.\%2f|\.\.\%5c|\.\.%252f|\.\.%255c)/i,
    /%(?:2e|c0%ae|e0%80%ae|c0ae|e0%80ae|25%63%30%61%65)(?:%2e|%c0%ae|%e0%80%ae|%c0ae|%e0%80ae|%25%63%30%61%65)/i,
    /(?:\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|boot\.ini|win\.ini|\/proc\/self\/environ)/i,
    /(?:\/\.\.\/|\\\.\.\\|%5c\.\.%5c|%2f\.\.%2f)/i,
    /(?:%00|%0a|%0d)/i,
    /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?/i,
    /https?:\/\/(?:[^.]+\.)?(?:internal|corp|local|intranet|private|localhost)(?:$|\/|:)/i,
  ],

  nosql: [
    /\$(?:ne|gt|lt|gte|lte|in|nin|not|or|and|regex|where|elemMatch|exists|type|mod|all|size|within|slice|max|min)/i,
    /\{\s*\$(?:gt|lt|gte|lte|ne|in|nin|not|or|and|regex|where)\s*:/i,
    /\$(?:function|eval|where)\s*:/i,
    /["']__proto__["']|["']constructor["']|["']prototype["']/i,
    /^\s*\{\s*\$[a-z]+:/i,
  ],

  templateInjection: [
    /\{\{\s*[\w\._\[\]\(\)]+\s*\}\}/i,
    /#\{.+?\}|\${.+?}|\$\{.+?\}|\<\%.+?\%\>/i,
    /\$\{[\w\._\[\]\(\)\'\"]+\}/i,
    /\{\{.*(?:constructor|prototype|window|document|eval|alert|confirm).*\}\}/i,
    /\{\{.*(?:constructor\.constructor|__proto__|Object\.|Function\.|eval\().*\}\}/i,
  ],
};
