var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toCommandProperties = exports2.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports2.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports2.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.issue = exports2.issueCommand = void 0;
    var os3 = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os3.EOL);
    }
    exports2.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports2.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/uuid/dist/esm-node/rng.js
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    import_crypto.default.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var import_crypto, rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    import_crypto = __toESM(require("crypto"));
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  const bytes = [];
  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto2.default.createHash("md5").update(bytes).digest();
}
var import_crypto2, md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    import_crypto2 = __toESM(require("crypto"));
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto3.default.createHash("sha1").update(bytes).digest();
}
var import_crypto3, sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    import_crypto3 = __toESM(require("crypto"));
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.prepareKeyValueMessage = exports2.issueFileCommand = void 0;
    var fs3 = __importStar(require("fs"));
    var os3 = __importStar(require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs3.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs3.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os3.EOL}`, {
        encoding: "utf8"
      });
    }
    exports2.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os3.EOL}${convertedValue}${os3.EOL}${delimiter}`;
    }
    exports2.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.checkBypass = exports2.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        try {
          return new URL(proxyVar);
        } catch (_a) {
          if (!proxyVar.startsWith("http://") && !proxyVar.startsWith("https://"))
            return new URL(`http://${proxyVar}`);
        }
      } else {
        return void 0;
      }
    }
    exports2.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const reqHost = reqUrl.hostname;
      if (isLoopbackAddress(reqHost)) {
        return true;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperNoProxyItem === "*" || upperReqHosts.some((x) => x === upperNoProxyItem || x.endsWith(`.${upperNoProxyItem}`) || upperNoProxyItem.startsWith(".") && x.endsWith(`${upperNoProxyItem}`))) {
          return true;
        }
      }
      return false;
    }
    exports2.checkBypass = checkBypass;
    function isLoopbackAddress(host) {
      const hostLower = host.toLowerCase();
      return hostLower === "localhost" || hostLower.startsWith("127.") || hostLower.startsWith("[::1]") || hostLower.startsWith("[0:0:0:0:0:0:0:1]");
    }
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports2) {
    "use strict";
    var net = require("net");
    var tls = require("tls");
    var http = require("http");
    var https = require("https");
    var events = require("events");
    var assert = require("assert");
    var util4 = require("util");
    exports2.httpOverHttp = httpOverHttp;
    exports2.httpsOverHttp = httpsOverHttp;
    exports2.httpOverHttps = httpOverHttps;
    exports2.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self = this;
      self.options = options || {};
      self.proxyOptions = self.options.proxy || {};
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
      self.requests = [];
      self.sockets = [];
      self.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self.removeSocket(socket);
      });
    }
    util4.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self = this;
      var options = mergeOptions({ request: req }, self.options, toOptions(host, port, localAddress));
      if (self.sockets.length >= this.maxSockets) {
        self.requests.push(options);
        return;
      }
      self.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this;
      var placeholder = {};
      self.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug2("making CONNECT request");
      var connectReq = self.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug2(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error2 = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug2("got illegal response body from proxy");
          socket.destroy();
          var error2 = new Error("got illegal response body from proxy");
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        debug2("tunneling connection has established");
        self.sockets[self.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug2(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error2 = new Error("tunneling socket could not be established, cause=" + cause.message);
        error2.code = "ECONNRESET";
        options.request.emit("error", error2);
        self.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self = this;
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self.sockets[self.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug2;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug2 = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug2 = function() {
      };
    }
    exports2.debug = debug2;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports2, module2) {
    module2.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.HttpClient = exports2.isHttps = exports2.HttpClientResponse = exports2.HttpClientError = exports2.getProxyUrl = exports2.MediaTypes = exports2.Headers = exports2.HttpCodes = void 0;
    var http = __importStar(require("http"));
    var https = __importStar(require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports2.HttpCodes || (exports2.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports2.Headers || (exports2.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports2.MediaTypes || (exports2.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports2.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class _HttpClientError extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, _HttpClientError.prototype);
      }
    };
    exports2.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve(output.toString());
            });
          }));
        });
      }
      readBodyBuffer() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
            const chunks = [];
            this.message.on("data", (chunk) => {
              chunks.push(chunk);
            });
            this.message.on("end", () => {
              resolve(Buffer.concat(chunks));
            });
          }));
        });
      }
    };
    exports2.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports2.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info2 = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info2, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info2, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info2 = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info2, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info2, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve(res);
              }
            }
            this.requestRawWithCallback(info2, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info2, data, onResult) {
        if (typeof data === "string") {
          if (!info2.options.headers) {
            info2.options.headers = {};
          }
          info2.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info2.httpModule.request(info2.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info2.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info2 = {};
        info2.parsedUrl = requestUrl;
        const usingSsl = info2.parsedUrl.protocol === "https:";
        info2.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info2.options = {};
        info2.options.host = info2.parsedUrl.hostname;
        info2.options.port = info2.parsedUrl.port ? parseInt(info2.parsedUrl.port) : defaultPort;
        info2.options.path = (info2.parsedUrl.pathname || "") + (info2.parsedUrl.search || "");
        info2.options.method = method;
        info2.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info2.options.headers["user-agent"] = this.userAgent;
        }
        info2.options.agent = this._getAgent(info2.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info2.options);
          }
        }
        return info2;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve) => setTimeout(() => resolve(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve(response);
            }
          }));
        });
      }
    };
    exports2.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.PersonalAccessTokenCredentialHandler = exports2.BearerCredentialHandler = exports2.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class _OidcClient {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(_OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = _OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error2) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error2.statusCode}
 
        Error Message: ${error2.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = _OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield _OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error2) {
            throw new Error(`Error message: ${error2.message}`);
          }
        });
      }
    };
    exports2.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.summary = exports2.markdownSummary = exports2.SUMMARY_DOCS_URL = exports2.SUMMARY_ENV_VAR = void 0;
    var os_1 = require("os");
    var fs_1 = require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports2.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports2.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports2.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports2.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports2.markdownSummary = _summary;
    exports2.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toPlatformPath = exports2.toWin32Path = exports2.toPosixPath = void 0;
    var path3 = __importStar(require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports2.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports2.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path3.sep);
    }
    exports2.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.getIDToken = exports2.getState = exports2.saveState = exports2.group = exports2.endGroup = exports2.startGroup = exports2.info = exports2.notice = exports2.warning = exports2.error = exports2.debug = exports2.isDebug = exports2.setFailed = exports2.setCommandEcho = exports2.setOutput = exports2.getBooleanInput = exports2.getMultilineInput = exports2.getInput = exports2.addPath = exports2.setSecret = exports2.exportVariable = exports2.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os3 = __importStar(require("os"));
    var path3 = __importStar(require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports2.ExitCode || (exports2.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports2.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports2.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path3.delimiter}${process.env["PATH"]}`;
    }
    exports2.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports2.getInput = getInput2;
    function getMultilineInput(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports2.getMultilineInput = getMultilineInput;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports2.getBooleanInput = getBooleanInput;
    function setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os3.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports2.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports2.setCommandEcho = setCommandEcho;
    function setFailed2(message) {
      process.exitCode = ExitCode.Failure;
      error2(message);
    }
    exports2.setFailed = setFailed2;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports2.isDebug = isDebug;
    function debug2(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports2.debug = debug2;
    function error2(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.error = error2;
    function warning2(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.warning = warning2;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.notice = notice;
    function info2(message) {
      process.stdout.write(message + os3.EOL);
    }
    exports2.info = info2;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports2.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports2.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports2.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports2.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports2.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports2.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports2, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports2, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports2, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports2, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports2, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/@actions/io/lib/io-util.js
var require_io_util = __commonJS({
  "node_modules/@actions/io/lib/io-util.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    var _a;
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.getCmdPath = exports2.tryGetExecutablePath = exports2.isRooted = exports2.isDirectory = exports2.exists = exports2.READONLY = exports2.UV_FS_O_EXLOCK = exports2.IS_WINDOWS = exports2.unlink = exports2.symlink = exports2.stat = exports2.rmdir = exports2.rm = exports2.rename = exports2.readlink = exports2.readdir = exports2.open = exports2.mkdir = exports2.lstat = exports2.copyFile = exports2.chmod = void 0;
    var fs3 = __importStar(require("fs"));
    var path3 = __importStar(require("path"));
    _a = fs3.promises, exports2.chmod = _a.chmod, exports2.copyFile = _a.copyFile, exports2.lstat = _a.lstat, exports2.mkdir = _a.mkdir, exports2.open = _a.open, exports2.readdir = _a.readdir, exports2.readlink = _a.readlink, exports2.rename = _a.rename, exports2.rm = _a.rm, exports2.rmdir = _a.rmdir, exports2.stat = _a.stat, exports2.symlink = _a.symlink, exports2.unlink = _a.unlink;
    exports2.IS_WINDOWS = process.platform === "win32";
    exports2.UV_FS_O_EXLOCK = 268435456;
    exports2.READONLY = fs3.constants.O_RDONLY;
    function exists(fsPath) {
      return __awaiter(this, void 0, void 0, function* () {
        try {
          yield exports2.stat(fsPath);
        } catch (err) {
          if (err.code === "ENOENT") {
            return false;
          }
          throw err;
        }
        return true;
      });
    }
    exports2.exists = exists;
    function isDirectory(fsPath, useStat = false) {
      return __awaiter(this, void 0, void 0, function* () {
        const stats = useStat ? yield exports2.stat(fsPath) : yield exports2.lstat(fsPath);
        return stats.isDirectory();
      });
    }
    exports2.isDirectory = isDirectory;
    function isRooted(p) {
      p = normalizeSeparators(p);
      if (!p) {
        throw new Error('isRooted() parameter "p" cannot be empty');
      }
      if (exports2.IS_WINDOWS) {
        return p.startsWith("\\") || /^[A-Z]:/i.test(p);
      }
      return p.startsWith("/");
    }
    exports2.isRooted = isRooted;
    function tryGetExecutablePath(filePath, extensions) {
      return __awaiter(this, void 0, void 0, function* () {
        let stats = void 0;
        try {
          stats = yield exports2.stat(filePath);
        } catch (err) {
          if (err.code !== "ENOENT") {
            console.log(`Unexpected error attempting to determine if executable file exists '${filePath}': ${err}`);
          }
        }
        if (stats && stats.isFile()) {
          if (exports2.IS_WINDOWS) {
            const upperExt = path3.extname(filePath).toUpperCase();
            if (extensions.some((validExt) => validExt.toUpperCase() === upperExt)) {
              return filePath;
            }
          } else {
            if (isUnixExecutable(stats)) {
              return filePath;
            }
          }
        }
        const originalFilePath = filePath;
        for (const extension of extensions) {
          filePath = originalFilePath + extension;
          stats = void 0;
          try {
            stats = yield exports2.stat(filePath);
          } catch (err) {
            if (err.code !== "ENOENT") {
              console.log(`Unexpected error attempting to determine if executable file exists '${filePath}': ${err}`);
            }
          }
          if (stats && stats.isFile()) {
            if (exports2.IS_WINDOWS) {
              try {
                const directory = path3.dirname(filePath);
                const upperName = path3.basename(filePath).toUpperCase();
                for (const actualName of yield exports2.readdir(directory)) {
                  if (upperName === actualName.toUpperCase()) {
                    filePath = path3.join(directory, actualName);
                    break;
                  }
                }
              } catch (err) {
                console.log(`Unexpected error attempting to determine the actual case of the file '${filePath}': ${err}`);
              }
              return filePath;
            } else {
              if (isUnixExecutable(stats)) {
                return filePath;
              }
            }
          }
        }
        return "";
      });
    }
    exports2.tryGetExecutablePath = tryGetExecutablePath;
    function normalizeSeparators(p) {
      p = p || "";
      if (exports2.IS_WINDOWS) {
        p = p.replace(/\//g, "\\");
        return p.replace(/\\\\+/g, "\\");
      }
      return p.replace(/\/\/+/g, "/");
    }
    function isUnixExecutable(stats) {
      return (stats.mode & 1) > 0 || (stats.mode & 8) > 0 && stats.gid === process.getgid() || (stats.mode & 64) > 0 && stats.uid === process.getuid();
    }
    function getCmdPath() {
      var _a2;
      return (_a2 = process.env["COMSPEC"]) !== null && _a2 !== void 0 ? _a2 : `cmd.exe`;
    }
    exports2.getCmdPath = getCmdPath;
  }
});

// node_modules/@actions/io/lib/io.js
var require_io = __commonJS({
  "node_modules/@actions/io/lib/io.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.findInPath = exports2.which = exports2.mkdirP = exports2.rmRF = exports2.mv = exports2.cp = void 0;
    var assert_1 = require("assert");
    var path3 = __importStar(require("path"));
    var ioUtil = __importStar(require_io_util());
    function cp(source, dest, options = {}) {
      return __awaiter(this, void 0, void 0, function* () {
        const { force, recursive, copySourceDirectory } = readCopyOptions(options);
        const destStat = (yield ioUtil.exists(dest)) ? yield ioUtil.stat(dest) : null;
        if (destStat && destStat.isFile() && !force) {
          return;
        }
        const newDest = destStat && destStat.isDirectory() && copySourceDirectory ? path3.join(dest, path3.basename(source)) : dest;
        if (!(yield ioUtil.exists(source))) {
          throw new Error(`no such file or directory: ${source}`);
        }
        const sourceStat = yield ioUtil.stat(source);
        if (sourceStat.isDirectory()) {
          if (!recursive) {
            throw new Error(`Failed to copy. ${source} is a directory, but tried to copy without recursive flag.`);
          } else {
            yield cpDirRecursive(source, newDest, 0, force);
          }
        } else {
          if (path3.relative(source, newDest) === "") {
            throw new Error(`'${newDest}' and '${source}' are the same file`);
          }
          yield copyFile(source, newDest, force);
        }
      });
    }
    exports2.cp = cp;
    function mv(source, dest, options = {}) {
      return __awaiter(this, void 0, void 0, function* () {
        if (yield ioUtil.exists(dest)) {
          let destExists = true;
          if (yield ioUtil.isDirectory(dest)) {
            dest = path3.join(dest, path3.basename(source));
            destExists = yield ioUtil.exists(dest);
          }
          if (destExists) {
            if (options.force == null || options.force) {
              yield rmRF(dest);
            } else {
              throw new Error("Destination already exists");
            }
          }
        }
        yield mkdirP(path3.dirname(dest));
        yield ioUtil.rename(source, dest);
      });
    }
    exports2.mv = mv;
    function rmRF(inputPath) {
      return __awaiter(this, void 0, void 0, function* () {
        if (ioUtil.IS_WINDOWS) {
          if (/[*"<>|]/.test(inputPath)) {
            throw new Error('File path must not contain `*`, `"`, `<`, `>` or `|` on Windows');
          }
        }
        try {
          yield ioUtil.rm(inputPath, {
            force: true,
            maxRetries: 3,
            recursive: true,
            retryDelay: 300
          });
        } catch (err) {
          throw new Error(`File was unable to be removed ${err}`);
        }
      });
    }
    exports2.rmRF = rmRF;
    function mkdirP(fsPath) {
      return __awaiter(this, void 0, void 0, function* () {
        assert_1.ok(fsPath, "a path argument must be provided");
        yield ioUtil.mkdir(fsPath, { recursive: true });
      });
    }
    exports2.mkdirP = mkdirP;
    function which2(tool, check) {
      return __awaiter(this, void 0, void 0, function* () {
        if (!tool) {
          throw new Error("parameter 'tool' is required");
        }
        if (check) {
          const result = yield which2(tool, false);
          if (!result) {
            if (ioUtil.IS_WINDOWS) {
              throw new Error(`Unable to locate executable file: ${tool}. Please verify either the file path exists or the file can be found within a directory specified by the PATH environment variable. Also verify the file has a valid extension for an executable file.`);
            } else {
              throw new Error(`Unable to locate executable file: ${tool}. Please verify either the file path exists or the file can be found within a directory specified by the PATH environment variable. Also check the file mode to verify the file is executable.`);
            }
          }
          return result;
        }
        const matches = yield findInPath(tool);
        if (matches && matches.length > 0) {
          return matches[0];
        }
        return "";
      });
    }
    exports2.which = which2;
    function findInPath(tool) {
      return __awaiter(this, void 0, void 0, function* () {
        if (!tool) {
          throw new Error("parameter 'tool' is required");
        }
        const extensions = [];
        if (ioUtil.IS_WINDOWS && process.env["PATHEXT"]) {
          for (const extension of process.env["PATHEXT"].split(path3.delimiter)) {
            if (extension) {
              extensions.push(extension);
            }
          }
        }
        if (ioUtil.isRooted(tool)) {
          const filePath = yield ioUtil.tryGetExecutablePath(tool, extensions);
          if (filePath) {
            return [filePath];
          }
          return [];
        }
        if (tool.includes(path3.sep)) {
          return [];
        }
        const directories = [];
        if (process.env.PATH) {
          for (const p of process.env.PATH.split(path3.delimiter)) {
            if (p) {
              directories.push(p);
            }
          }
        }
        const matches = [];
        for (const directory of directories) {
          const filePath = yield ioUtil.tryGetExecutablePath(path3.join(directory, tool), extensions);
          if (filePath) {
            matches.push(filePath);
          }
        }
        return matches;
      });
    }
    exports2.findInPath = findInPath;
    function readCopyOptions(options) {
      const force = options.force == null ? true : options.force;
      const recursive = Boolean(options.recursive);
      const copySourceDirectory = options.copySourceDirectory == null ? true : Boolean(options.copySourceDirectory);
      return { force, recursive, copySourceDirectory };
    }
    function cpDirRecursive(sourceDir, destDir, currentDepth, force) {
      return __awaiter(this, void 0, void 0, function* () {
        if (currentDepth >= 255)
          return;
        currentDepth++;
        yield mkdirP(destDir);
        const files = yield ioUtil.readdir(sourceDir);
        for (const fileName of files) {
          const srcFile = `${sourceDir}/${fileName}`;
          const destFile = `${destDir}/${fileName}`;
          const srcFileStat = yield ioUtil.lstat(srcFile);
          if (srcFileStat.isDirectory()) {
            yield cpDirRecursive(srcFile, destFile, currentDepth, force);
          } else {
            yield copyFile(srcFile, destFile, force);
          }
        }
        yield ioUtil.chmod(destDir, (yield ioUtil.stat(sourceDir)).mode);
      });
    }
    function copyFile(srcFile, destFile, force) {
      return __awaiter(this, void 0, void 0, function* () {
        if ((yield ioUtil.lstat(srcFile)).isSymbolicLink()) {
          try {
            yield ioUtil.lstat(destFile);
            yield ioUtil.unlink(destFile);
          } catch (e) {
            if (e.code === "EPERM") {
              yield ioUtil.chmod(destFile, "0666");
              yield ioUtil.unlink(destFile);
            }
          }
          const symlinkFull = yield ioUtil.readlink(srcFile);
          yield ioUtil.symlink(symlinkFull, destFile, ioUtil.IS_WINDOWS ? "junction" : null);
        } else if (!(yield ioUtil.exists(destFile)) || force) {
          yield ioUtil.copyFile(srcFile, destFile);
        }
      });
    }
  }
});

// node_modules/@actions/exec/lib/toolrunner.js
var require_toolrunner = __commonJS({
  "node_modules/@actions/exec/lib/toolrunner.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.argStringToArray = exports2.ToolRunner = void 0;
    var os3 = __importStar(require("os"));
    var events = __importStar(require("events"));
    var child = __importStar(require("child_process"));
    var path3 = __importStar(require("path"));
    var io2 = __importStar(require_io());
    var ioUtil = __importStar(require_io_util());
    var timers_1 = require("timers");
    var IS_WINDOWS = process.platform === "win32";
    var ToolRunner = class extends events.EventEmitter {
      constructor(toolPath, args, options) {
        super();
        if (!toolPath) {
          throw new Error("Parameter 'toolPath' cannot be null or empty.");
        }
        this.toolPath = toolPath;
        this.args = args || [];
        this.options = options || {};
      }
      _debug(message) {
        if (this.options.listeners && this.options.listeners.debug) {
          this.options.listeners.debug(message);
        }
      }
      _getCommandString(options, noPrefix) {
        const toolPath = this._getSpawnFileName();
        const args = this._getSpawnArgs(options);
        let cmd = noPrefix ? "" : "[command]";
        if (IS_WINDOWS) {
          if (this._isCmdFile()) {
            cmd += toolPath;
            for (const a of args) {
              cmd += ` ${a}`;
            }
          } else if (options.windowsVerbatimArguments) {
            cmd += `"${toolPath}"`;
            for (const a of args) {
              cmd += ` ${a}`;
            }
          } else {
            cmd += this._windowsQuoteCmdArg(toolPath);
            for (const a of args) {
              cmd += ` ${this._windowsQuoteCmdArg(a)}`;
            }
          }
        } else {
          cmd += toolPath;
          for (const a of args) {
            cmd += ` ${a}`;
          }
        }
        return cmd;
      }
      _processLineBuffer(data, strBuffer, onLine) {
        try {
          let s = strBuffer + data.toString();
          let n = s.indexOf(os3.EOL);
          while (n > -1) {
            const line = s.substring(0, n);
            onLine(line);
            s = s.substring(n + os3.EOL.length);
            n = s.indexOf(os3.EOL);
          }
          return s;
        } catch (err) {
          this._debug(`error processing line. Failed with error ${err}`);
          return "";
        }
      }
      _getSpawnFileName() {
        if (IS_WINDOWS) {
          if (this._isCmdFile()) {
            return process.env["COMSPEC"] || "cmd.exe";
          }
        }
        return this.toolPath;
      }
      _getSpawnArgs(options) {
        if (IS_WINDOWS) {
          if (this._isCmdFile()) {
            let argline = `/D /S /C "${this._windowsQuoteCmdArg(this.toolPath)}`;
            for (const a of this.args) {
              argline += " ";
              argline += options.windowsVerbatimArguments ? a : this._windowsQuoteCmdArg(a);
            }
            argline += '"';
            return [argline];
          }
        }
        return this.args;
      }
      _endsWith(str, end) {
        return str.endsWith(end);
      }
      _isCmdFile() {
        const upperToolPath = this.toolPath.toUpperCase();
        return this._endsWith(upperToolPath, ".CMD") || this._endsWith(upperToolPath, ".BAT");
      }
      _windowsQuoteCmdArg(arg) {
        if (!this._isCmdFile()) {
          return this._uvQuoteCmdArg(arg);
        }
        if (!arg) {
          return '""';
        }
        const cmdSpecialChars = [
          " ",
          "	",
          "&",
          "(",
          ")",
          "[",
          "]",
          "{",
          "}",
          "^",
          "=",
          ";",
          "!",
          "'",
          "+",
          ",",
          "`",
          "~",
          "|",
          "<",
          ">",
          '"'
        ];
        let needsQuotes = false;
        for (const char of arg) {
          if (cmdSpecialChars.some((x) => x === char)) {
            needsQuotes = true;
            break;
          }
        }
        if (!needsQuotes) {
          return arg;
        }
        let reverse = '"';
        let quoteHit = true;
        for (let i = arg.length; i > 0; i--) {
          reverse += arg[i - 1];
          if (quoteHit && arg[i - 1] === "\\") {
            reverse += "\\";
          } else if (arg[i - 1] === '"') {
            quoteHit = true;
            reverse += '"';
          } else {
            quoteHit = false;
          }
        }
        reverse += '"';
        return reverse.split("").reverse().join("");
      }
      _uvQuoteCmdArg(arg) {
        if (!arg) {
          return '""';
        }
        if (!arg.includes(" ") && !arg.includes("	") && !arg.includes('"')) {
          return arg;
        }
        if (!arg.includes('"') && !arg.includes("\\")) {
          return `"${arg}"`;
        }
        let reverse = '"';
        let quoteHit = true;
        for (let i = arg.length; i > 0; i--) {
          reverse += arg[i - 1];
          if (quoteHit && arg[i - 1] === "\\") {
            reverse += "\\";
          } else if (arg[i - 1] === '"') {
            quoteHit = true;
            reverse += "\\";
          } else {
            quoteHit = false;
          }
        }
        reverse += '"';
        return reverse.split("").reverse().join("");
      }
      _cloneExecOptions(options) {
        options = options || {};
        const result = {
          cwd: options.cwd || process.cwd(),
          env: options.env || process.env,
          silent: options.silent || false,
          windowsVerbatimArguments: options.windowsVerbatimArguments || false,
          failOnStdErr: options.failOnStdErr || false,
          ignoreReturnCode: options.ignoreReturnCode || false,
          delay: options.delay || 1e4
        };
        result.outStream = options.outStream || process.stdout;
        result.errStream = options.errStream || process.stderr;
        return result;
      }
      _getSpawnOptions(options, toolPath) {
        options = options || {};
        const result = {};
        result.cwd = options.cwd;
        result.env = options.env;
        result["windowsVerbatimArguments"] = options.windowsVerbatimArguments || this._isCmdFile();
        if (options.windowsVerbatimArguments) {
          result.argv0 = `"${toolPath}"`;
        }
        return result;
      }
      /**
       * Exec a tool.
       * Output will be streamed to the live console.
       * Returns promise with return code
       *
       * @param     tool     path to tool to exec
       * @param     options  optional exec options.  See ExecOptions
       * @returns   number
       */
      exec() {
        return __awaiter(this, void 0, void 0, function* () {
          if (!ioUtil.isRooted(this.toolPath) && (this.toolPath.includes("/") || IS_WINDOWS && this.toolPath.includes("\\"))) {
            this.toolPath = path3.resolve(process.cwd(), this.options.cwd || process.cwd(), this.toolPath);
          }
          this.toolPath = yield io2.which(this.toolPath, true);
          return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            this._debug(`exec tool: ${this.toolPath}`);
            this._debug("arguments:");
            for (const arg of this.args) {
              this._debug(`   ${arg}`);
            }
            const optionsNonNull = this._cloneExecOptions(this.options);
            if (!optionsNonNull.silent && optionsNonNull.outStream) {
              optionsNonNull.outStream.write(this._getCommandString(optionsNonNull) + os3.EOL);
            }
            const state = new ExecState(optionsNonNull, this.toolPath);
            state.on("debug", (message) => {
              this._debug(message);
            });
            if (this.options.cwd && !(yield ioUtil.exists(this.options.cwd))) {
              return reject(new Error(`The cwd: ${this.options.cwd} does not exist!`));
            }
            const fileName = this._getSpawnFileName();
            const cp = child.spawn(fileName, this._getSpawnArgs(optionsNonNull), this._getSpawnOptions(this.options, fileName));
            let stdbuffer = "";
            if (cp.stdout) {
              cp.stdout.on("data", (data) => {
                if (this.options.listeners && this.options.listeners.stdout) {
                  this.options.listeners.stdout(data);
                }
                if (!optionsNonNull.silent && optionsNonNull.outStream) {
                  optionsNonNull.outStream.write(data);
                }
                stdbuffer = this._processLineBuffer(data, stdbuffer, (line) => {
                  if (this.options.listeners && this.options.listeners.stdline) {
                    this.options.listeners.stdline(line);
                  }
                });
              });
            }
            let errbuffer = "";
            if (cp.stderr) {
              cp.stderr.on("data", (data) => {
                state.processStderr = true;
                if (this.options.listeners && this.options.listeners.stderr) {
                  this.options.listeners.stderr(data);
                }
                if (!optionsNonNull.silent && optionsNonNull.errStream && optionsNonNull.outStream) {
                  const s = optionsNonNull.failOnStdErr ? optionsNonNull.errStream : optionsNonNull.outStream;
                  s.write(data);
                }
                errbuffer = this._processLineBuffer(data, errbuffer, (line) => {
                  if (this.options.listeners && this.options.listeners.errline) {
                    this.options.listeners.errline(line);
                  }
                });
              });
            }
            cp.on("error", (err) => {
              state.processError = err.message;
              state.processExited = true;
              state.processClosed = true;
              state.CheckComplete();
            });
            cp.on("exit", (code) => {
              state.processExitCode = code;
              state.processExited = true;
              this._debug(`Exit code ${code} received from tool '${this.toolPath}'`);
              state.CheckComplete();
            });
            cp.on("close", (code) => {
              state.processExitCode = code;
              state.processExited = true;
              state.processClosed = true;
              this._debug(`STDIO streams have closed for tool '${this.toolPath}'`);
              state.CheckComplete();
            });
            state.on("done", (error2, exitCode) => {
              if (stdbuffer.length > 0) {
                this.emit("stdline", stdbuffer);
              }
              if (errbuffer.length > 0) {
                this.emit("errline", errbuffer);
              }
              cp.removeAllListeners();
              if (error2) {
                reject(error2);
              } else {
                resolve(exitCode);
              }
            });
            if (this.options.input) {
              if (!cp.stdin) {
                throw new Error("child process missing stdin");
              }
              cp.stdin.end(this.options.input);
            }
          }));
        });
      }
    };
    exports2.ToolRunner = ToolRunner;
    function argStringToArray(argString) {
      const args = [];
      let inQuotes = false;
      let escaped = false;
      let arg = "";
      function append(c) {
        if (escaped && c !== '"') {
          arg += "\\";
        }
        arg += c;
        escaped = false;
      }
      for (let i = 0; i < argString.length; i++) {
        const c = argString.charAt(i);
        if (c === '"') {
          if (!escaped) {
            inQuotes = !inQuotes;
          } else {
            append(c);
          }
          continue;
        }
        if (c === "\\" && escaped) {
          append(c);
          continue;
        }
        if (c === "\\" && inQuotes) {
          escaped = true;
          continue;
        }
        if (c === " " && !inQuotes) {
          if (arg.length > 0) {
            args.push(arg);
            arg = "";
          }
          continue;
        }
        append(c);
      }
      if (arg.length > 0) {
        args.push(arg.trim());
      }
      return args;
    }
    exports2.argStringToArray = argStringToArray;
    var ExecState = class _ExecState extends events.EventEmitter {
      constructor(options, toolPath) {
        super();
        this.processClosed = false;
        this.processError = "";
        this.processExitCode = 0;
        this.processExited = false;
        this.processStderr = false;
        this.delay = 1e4;
        this.done = false;
        this.timeout = null;
        if (!toolPath) {
          throw new Error("toolPath must not be empty");
        }
        this.options = options;
        this.toolPath = toolPath;
        if (options.delay) {
          this.delay = options.delay;
        }
      }
      CheckComplete() {
        if (this.done) {
          return;
        }
        if (this.processClosed) {
          this._setResult();
        } else if (this.processExited) {
          this.timeout = timers_1.setTimeout(_ExecState.HandleTimeout, this.delay, this);
        }
      }
      _debug(message) {
        this.emit("debug", message);
      }
      _setResult() {
        let error2;
        if (this.processExited) {
          if (this.processError) {
            error2 = new Error(`There was an error when attempting to execute the process '${this.toolPath}'. This may indicate the process failed to start. Error: ${this.processError}`);
          } else if (this.processExitCode !== 0 && !this.options.ignoreReturnCode) {
            error2 = new Error(`The process '${this.toolPath}' failed with exit code ${this.processExitCode}`);
          } else if (this.processStderr && this.options.failOnStdErr) {
            error2 = new Error(`The process '${this.toolPath}' failed because one or more lines were written to the STDERR stream`);
          }
        }
        if (this.timeout) {
          clearTimeout(this.timeout);
          this.timeout = null;
        }
        this.done = true;
        this.emit("done", error2, this.processExitCode);
      }
      static HandleTimeout(state) {
        if (state.done) {
          return;
        }
        if (!state.processClosed && state.processExited) {
          const message = `The STDIO streams did not close within ${state.delay / 1e3} seconds of the exit event from process '${state.toolPath}'. This may indicate a child process inherited the STDIO streams and has not yet exited.`;
          state._debug(message);
        }
        state._setResult();
      }
    };
  }
});

// node_modules/@actions/exec/lib/exec.js
var require_exec = __commonJS({
  "node_modules/@actions/exec/lib/exec.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.getExecOutput = exports2.exec = void 0;
    var string_decoder_1 = require("string_decoder");
    var tr = __importStar(require_toolrunner());
    function exec3(commandLine, args, options) {
      return __awaiter(this, void 0, void 0, function* () {
        const commandArgs = tr.argStringToArray(commandLine);
        if (commandArgs.length === 0) {
          throw new Error(`Parameter 'commandLine' cannot be null or empty.`);
        }
        const toolPath = commandArgs[0];
        args = commandArgs.slice(1).concat(args || []);
        const runner = new tr.ToolRunner(toolPath, args, options);
        return runner.exec();
      });
    }
    exports2.exec = exec3;
    function getExecOutput(commandLine, args, options) {
      var _a, _b;
      return __awaiter(this, void 0, void 0, function* () {
        let stdout = "";
        let stderr = "";
        const stdoutDecoder = new string_decoder_1.StringDecoder("utf8");
        const stderrDecoder = new string_decoder_1.StringDecoder("utf8");
        const originalStdoutListener = (_a = options === null || options === void 0 ? void 0 : options.listeners) === null || _a === void 0 ? void 0 : _a.stdout;
        const originalStdErrListener = (_b = options === null || options === void 0 ? void 0 : options.listeners) === null || _b === void 0 ? void 0 : _b.stderr;
        const stdErrListener = (data) => {
          stderr += stderrDecoder.write(data);
          if (originalStdErrListener) {
            originalStdErrListener(data);
          }
        };
        const stdOutListener = (data) => {
          stdout += stdoutDecoder.write(data);
          if (originalStdoutListener) {
            originalStdoutListener(data);
          }
        };
        const listeners = Object.assign(Object.assign({}, options === null || options === void 0 ? void 0 : options.listeners), { stdout: stdOutListener, stderr: stdErrListener });
        const exitCode = yield exec3(commandLine, args, Object.assign(Object.assign({}, options), { listeners }));
        stdout += stdoutDecoder.end();
        stderr += stderrDecoder.end();
        return {
          exitCode,
          stdout,
          stderr
        };
      });
    }
    exports2.getExecOutput = getExecOutput;
  }
});

// azurecontainerapps.ts
var azurecontainerapps_exports = {};
__export(azurecontainerapps_exports, {
  azurecontainerapps: () => azurecontainerapps
});
module.exports = __toCommonJS(azurecontainerapps_exports);
var fs2 = __toESM(require("fs"));
var path2 = __toESM(require("path"));

// src/ContainerAppHelper.ts
var path = __toESM(require("path"));
var os = __toESM(require("os"));

// src/GitHubActionsToolHelper.ts
var core = __toESM(require_core());
var io = __toESM(require_io());
var exec = __toESM(require_exec());
var GitHubActionsToolHelper = class {
  getBuildId() {
    return process.env["GITHUB_RUN_ID"] || "";
  }
  getBuildNumber() {
    return process.env["GITHUB_RUN_NUMBER"] || "";
  }
  writeInfo(message) {
    core.info(message);
  }
  writeError(message) {
    core.error(message);
  }
  writeWarning(message) {
    core.warning(message);
  }
  writeDebug(message) {
    core.debug(message);
  }
  async exec(commandLine, args, inputOptions) {
    try {
      let stdout = "";
      let stderr = "";
      const options = {
        listeners: {
          stdout: (data) => {
            stdout += data.toString().replace(/(\r\n|\n|\r)/gm, "");
          },
          stderr: (data) => {
            stderr += data.toString();
          }
        },
        input: inputOptions
      };
      let exitCode = await exec.exec(commandLine, args, options);
      return new Promise((resolve, reject) => {
        let executionResult = {
          exitCode,
          stdout,
          stderr
        };
        resolve(executionResult);
      });
    } catch (err) {
      throw err;
    }
  }
  getInput(name, required) {
    const options = {
      required
    };
    return core.getInput(name, options);
  }
  setFailed(message) {
    core.setFailed(message);
  }
  which(tool, check) {
    return io.which(tool, check);
  }
  getDefaultContainerAppName(containerAppName) {
    containerAppName = `gh-action-app-${this.getBuildId()}-${this.getBuildNumber()}`;
    containerAppName = containerAppName.replace(/\./gi, "-");
    this.writeInfo(`Default Container App name: ${containerAppName}`);
    return containerAppName;
  }
  getTelemetryArg() {
    return `CALLER_ID=github-actions-v2`;
  }
  getEventName() {
    return `ContainerAppsGitHubActionV2`;
  }
  getDefaultImageRepository() {
    return `gh-action/container-app`;
  }
};

// src/Utility.ts
var toolHelper = new GitHubActionsToolHelper();
var Utility = class {
  /**
   * @param commandLine - the command to execute
   * @param args - the arguments to pass to the command
   * @param continueOnError - whether or not to continue execution if the command fails
   */
  async execute(commandLine, args, inputOptions) {
    return await toolHelper.exec(commandLine, args, inputOptions);
  }
  /**
   * Sets the Azure CLI to install the containerapp extension.
   */
  async installAzureCliExtension() {
    await this.execute(`az extension add --name containerapp --upgrade`);
  }
  /**
   * Checks whether or not the provided string is null, undefined or empty.
   * @param str - the string to validate
   * @returns true if the string is null, undefined or empty, false otherwise
   */
  isNullOrEmpty(str) {
    return str === null || str === void 0 || str === "";
  }
};

// src/ContainerAppHelper.ts
var fs = require("fs");
var ORYX_CLI_IMAGE = "mcr.microsoft.com/oryx/cli:builder-debian-bullseye-20230926.1";
var ORYX_BULLSEYE_BUILDER_IMAGE = "mcr.microsoft.com/oryx/builder:debian-bullseye-20240124.1";
var ORYX_BOOKWORM_BUILDER_IMAGE = "mcr.microsoft.com/oryx/builder:debian-bookworm-20240124.1";
var ORYX_BUILDER_IMAGES = [ORYX_BULLSEYE_BUILDER_IMAGE, ORYX_BOOKWORM_BUILDER_IMAGE];
var IS_WINDOWS_AGENT = os.platform() == "win32";
var PACK_CMD = IS_WINDOWS_AGENT ? path.join(os.tmpdir(), "pack") : "pack";
var toolHelper2 = new GitHubActionsToolHelper();
var util = new Utility();
var ContainerAppHelper = class {
  constructor(disableTelemetry) {
    this.disableTelemetry = false;
    this.disableTelemetry = disableTelemetry;
  }
  /**
   * Creates an Azure Container App.
   * @param containerAppName - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
   * @param environment - the Container App Environment that will be associated with the Container App
   * @param optionalCmdArgs - a set of optional command line arguments
   */
  async createContainerApp(containerAppName, resourceGroup, environment, optionalCmdArgs) {
    toolHelper2.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp create -n ${containerAppName} -g ${resourceGroup} --environment ${environment} --output none`;
      optionalCmdArgs.forEach(function(val) {
        command += ` ${val}`;
      });
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
  * Creates an Azure Container App.
  * @param containerAppName - the name of the Container App
  * @param resourceGroup - the resource group that the Container App is found in
  * @param optionalCmdArgs - a set of optional command line arguments
  */
  async createOrUpdateContainerAppWithUp(containerAppName, resourceGroup, optionalCmdArgs) {
    toolHelper2.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp up -n ${containerAppName} -g ${resourceGroup}`;
      optionalCmdArgs.forEach(function(val) {
        command += ` ${val}`;
      });
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Get the current subscription
   * @returns the current subscription
   */
  async getCurrentSubscription() {
    toolHelper2.writeDebug(`Attempting to get the default subscription`);
    try {
      let command = ` az account show --query id --output tsv `;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase() : ``;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return ``;
    }
  }
  /**
   * Creates an Azure Container App based from a YAML configuration file.
   * @param containerAppName - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
   * @param yamlConfigPath - the path to the YAML configuration file that the Container App properties will be based from
   */
  async createContainerAppFromYaml(containerAppName, resourceGroup, yamlConfigPath) {
    toolHelper2.writeDebug(`Attempting to create Container App with name "${containerAppName}" in resource group "${resourceGroup}" from provided YAML "${yamlConfigPath}"`);
    try {
      let command = `az containerapp create -n ${containerAppName} -g ${resourceGroup} --yaml ${yamlConfigPath} --output none`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Updates an existing Azure Container App based from an image that was previously built.
   * @param containerAppName - the name of the existing Container App
   * @param resourceGroup - the resource group that the existing Container App is found in
   * @param optionalCmdArgs - a set of optional command line arguments
   */
  async updateContainerApp(containerAppName, resourceGroup, optionalCmdArgs) {
    toolHelper2.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}" `);
    try {
      let command = `az containerapp update -n ${containerAppName} -g ${resourceGroup} --output none`;
      optionalCmdArgs.forEach(function(val) {
        command += ` ${val}`;
      });
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Updates an existing Azure Container App using the 'az containerapp up' command.
   * @param containerAppName - the name of the existing Container App
   * @param resourceGroup - the resource group that the existing Container App is found in
   * @param optionalCmdArgs - a set of optional command line arguments
   * @param ingress - the ingress that the Container App will be exposed on
   * @param targetPort - the target port that the Container App will be exposed on
   */
  async updateContainerAppWithUp(containerAppName, resourceGroup, optionalCmdArgs, ingress, targetPort) {
    toolHelper2.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp up -n ${containerAppName} -g ${resourceGroup}`;
      optionalCmdArgs.forEach(function(val) {
        command += ` ${val}`;
      });
      if (!util.isNullOrEmpty(ingress)) {
        command += ` --ingress ${ingress}`;
      }
      if (!util.isNullOrEmpty(targetPort)) {
        command += ` --target-port ${targetPort}`;
      }
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Update container app with update and ingress update to avoid failure of acr authentication.
   * @param containerAppName - the name of the existing Container App
   * @param resourceGroup - the resource group that the existing Container App is found in
   * @param ingress - the ingress that the Container App will be exposed on
   * @param targetPort - the target port that the Container App will be exposed on
   */
  async updateContainerAppIngress(containerAppName, resourceGroup, ingress, targetPort) {
    toolHelper2.writeDebug(`Attempting to update Container App ingress with name "${containerAppName}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp ingress update -n ${containerAppName} -g ${resourceGroup}`;
      if (!util.isNullOrEmpty(ingress)) {
        command += ` --type ${ingress}`;
      }
      if (!util.isNullOrEmpty(targetPort)) {
        command += ` --target-port ${targetPort}`;
      }
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Updates an existing Azure Container App based from a YAML configuration file.
   * @param containerAppName - the name of the existing Container App
   * @param resourceGroup - the resource group that the existing Container App is found in
   * @param yamlConfigPath - the path to the YAML configuration file that the Container App properties will be based from
   */
  async updateContainerAppFromYaml(containerAppName, resourceGroup, yamlConfigPath) {
    toolHelper2.writeDebug(`Attempting to update Container App with name "${containerAppName}" in resource group "${resourceGroup}" from provided YAML "${yamlConfigPath}"`);
    try {
      let command = `az containerapp update -n ${containerAppName} -g ${resourceGroup} --yaml ${yamlConfigPath} --output none`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Determines if the provided Container App exists in the provided resource group.
   * @param containerAppName - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
   * @returns true if the Container App exists, false otherwise
   */
  async doesContainerAppExist(containerAppName, resourceGroup) {
    toolHelper2.writeDebug(`Attempting to determine if Container App with name "${containerAppName}" exists in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp show -n ${containerAppName} -g ${resourceGroup} -o none`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return false;
    }
  }
  /**
   * Determines if the provided Container App Environment exists in the provided resource group.
   * @param containerAppEnvironment - the name of the Container App Environment
   * @param resourceGroup - the resource group that the Container App Environment is found in
   * @returns true if the Container App Environment exists, false otherwise
   */
  async doesContainerAppEnvironmentExist(containerAppEnvironment, resourceGroup) {
    toolHelper2.writeDebug(`Attempting to determine if Container App Environment with name "${containerAppEnvironment}" exists in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp env show -o none -g ${resourceGroup} -n ${containerAppEnvironment}`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return false;
    }
  }
  /**
   * Determines if the provided resource group exists.
   * @param resourceGroup - the name of the resource group
   * @returns true if the resource group exists, false otherwise
   */
  async doesResourceGroupExist(resourceGroup) {
    toolHelper2.writeDebug(`Attempting to determine if resource group "${resourceGroup}" exists`);
    try {
      let command = `az group show -n ${resourceGroup} -o none`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return false;
    }
  }
  /**
   * Gets the default location for the Container App provider.
   * @returns the default location if found, otherwise 'eastus2'
   */
  async getDefaultContainerAppLocation() {
    toolHelper2.writeDebug(`Attempting to get the default location for the Container App service for the subscription.`);
    try {
      let command = `az provider show -n Microsoft.App --query "resourceTypes[?resourceType=='containerApps'].locations[] | [0]"`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase().replace(/["() ]/g, "").trim() : `eastus2`;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return `eastus2`;
    }
  }
  /**
   * Creates a new resource group in the provided location.
   * @param name - the name of the resource group to create
   * @param location - the location to create the resource group in
   */
  async createResourceGroup(name, location) {
    toolHelper2.writeDebug(`Attempting to create resource group "${name}" in location "${location}"`);
    try {
      let command = `az group create -n ${name} -l ${location}`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Gets the name of an existing Container App Environment in the provided resource group.
   * @param resourceGroup - the resource group to check for an existing Container App Environment
   * @returns the name of the existing Container App Environment, null if none exists
   */
  async getExistingContainerAppEnvironment(resourceGroup) {
    toolHelper2.writeDebug(`Attempting to get the existing Container App Environment in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp env list -g ${resourceGroup} --query "[0].name"`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0 ? executionResult.stdout : null;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return null;
    }
  }
  /**
   * Gets the location of an existing Container App Environment
   * @param environmentName - the name of the Container App Environment
   * @param resourceGroup - the resource group that the Container App Environment is found in
  */
  async getExistingContainerAppEnvironmentLocation(environmentName, resourceGroup) {
    try {
      let command = `az containerapp env show -g ${resourceGroup} --query location -n ${environmentName}`;
      let executionResult = await util.execute(command);
      return executionResult.exitCode === 0 ? executionResult.stdout.toLowerCase().replace(/["() ]/g, "").trim() : null;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return null;
    }
  }
  /**
   * Gets the environment name of an existing Container App
   * @param containerAppName - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
  */
  async getExistingContainerAppEnvironmentName(containerAppName, resourceGroup) {
    try {
      let command = `az containerapp show -n ${containerAppName} -g ${resourceGroup} --query properties.environmentId`;
      let executionResult = await util.execute(command);
      let containerappEnvironmentId = executionResult.stdout.trim();
      if (!util.isNullOrEmpty(containerappEnvironmentId)) {
        containerappEnvironmentId = containerappEnvironmentId.endsWith("/") ? containerappEnvironmentId.slice(0, -1) : containerappEnvironmentId;
      }
      return executionResult.exitCode === 0 ? containerappEnvironmentId.split("/").pop().trim() : null;
    } catch (err) {
      toolHelper2.writeInfo(err.message);
      return null;
    }
  }
  /**
   * Creates a new Azure Container App Environment in the provided resource group.
   * @param name - the name of the Container App Environment
   * @param resourceGroup - the resource group that the Container App Environment will be created in
   * @param location - the location that the Container App Environment will be created in
   */
  async createContainerAppEnvironment(name, resourceGroup, location) {
    const util4 = new Utility();
    toolHelper2.writeDebug(`Attempting to create Container App Environment with name "${name}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp env create -n ${name} -g ${resourceGroup}`;
      if (!util4.isNullOrEmpty(location)) {
        command += ` -l ${location}`;
      }
      await util4.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Disables ingress on an existing Container App.
   * @param name - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
   */
  async disableContainerAppIngress(name, resourceGroup) {
    toolHelper2.writeDebug(`Attempting to disable ingress for Container App with name "${name}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp ingress disable -n ${name} -g ${resourceGroup}`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Updates the Container Registry details on an existing Container App.
   * @param name - the name of the Container App
   * @param resourceGroup - the resource group that the Container App is found in
   * @param registryUrl - the name of the Container Registry
   * @param registryUsername - the username used to authenticate with the Container Registry
   * @param registryPassword - the password used to authenticate with the Container Registry
   */
  async updateContainerAppRegistryDetails(name, resourceGroup, registryUrl, registryUsername, registryPassword) {
    toolHelper2.writeDebug(`Attempting to set the Container Registry details for Container App with name "${name}" in resource group "${resourceGroup}"`);
    try {
      let command = `az containerapp registry set -n ${name} -g ${resourceGroup} --server ${registryUrl} --username ${registryUsername} --password ${registryPassword}`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Using the Oryx++ Builder, creates a runnable application image from the provided application source.
   * @param imageToDeploy - the name of the runnable application image that is created and can be later deployed
   * @param appSourcePath - the path to the application source on the machine
   * @param environmentVariables - an array of environment variables that should be provided to the builder via the `--env` flag
   * @param builderStack - the stack to use when building the provided application source
   */
  async createRunnableAppImage(imageToDeploy, appSourcePath, environmentVariables, builderStack) {
    let telemetryArg = toolHelper2.getTelemetryArg();
    if (this.disableTelemetry) {
      telemetryArg = `ORYX_DISABLE_TELEMETRY=true`;
    }
    let subscription = await this.getCurrentSubscription();
    let couldBuildImage = false;
    for (const builderImage of ORYX_BUILDER_IMAGES) {
      if (!util.isNullOrEmpty(builderStack) && !builderImage.includes(builderStack)) {
        continue;
      }
      toolHelper2.writeDebug(`Attempting to create a runnable application image with name "${imageToDeploy}" using the Oryx++ Builder "${builderImage}"`);
      try {
        let command = `build ${imageToDeploy} --path ${appSourcePath} --builder ${builderImage} --env ${telemetryArg} --env BP_SUBSCRIPTION_ID=${subscription}`;
        environmentVariables.forEach(function(envVar) {
          command += ` --env ${envVar}`;
        });
        await util.execute(`${PACK_CMD} ${command}`);
        couldBuildImage = true;
        break;
      } catch (err) {
        toolHelper2.writeWarning(`Unable to run 'pack build' command to produce runnable application image: ${err.message}`);
      }
    }
    ;
    if (!couldBuildImage) {
      const errorMessage = `No builder was able to build the provided application source. Please visit the following page for more information on supported platform versions: https://aka.ms/SourceToCloudSupportedVersions`;
      toolHelper2.writeError(errorMessage);
      throw new Error(errorMessage);
    }
  }
  /**
   * Using a Dockerfile that was provided or found at the root of the application source,
   * creates a runable application image.
   * @param imageToDeploy - the name of the runnable application image that is created and can be later deployed
   * @param appSourcePath - the path to the application source on the machine
   * @param dockerfilePath - the path to the Dockerfile to build and tag with the provided image name
   * @param buildArguments - an array of build arguments that should be provided to the docker build command via the `--build-arg` flag
   */
  async createRunnableAppImageFromDockerfile(imageToDeploy, appSourcePath, dockerfilePath, buildArguments) {
    toolHelper2.writeDebug(`Attempting to create a runnable application image from the provided/found Dockerfile "${dockerfilePath}" with image name "${imageToDeploy}"`);
    try {
      let command = `docker build --file ${dockerfilePath} ${appSourcePath} --tag ${imageToDeploy}`;
      if (buildArguments.length > 0) {
        buildArguments.forEach(function(buildArg) {
          command += ` --build-arg ${buildArg}`;
        });
      }
      await util.execute(command);
      toolHelper2.writeDebug(`Successfully created runnable application image from the provided/found Dockerfile "${dockerfilePath}" with image name "${imageToDeploy}"`);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Determines the runtime stack to use for the runnable application image.
   * @param appSourcePath - the path to the application source on the machine
   * @returns a string representing the runtime stack that can be used for the Oryx MCR runtime images
   */
  async determineRuntimeStackAsync(appSourcePath) {
    toolHelper2.writeDebug("Attempting to determine the runtime stack needed for the provided application source");
    try {
      let command = `docker run --rm -v ${appSourcePath}:/app ${ORYX_CLI_IMAGE} /bin/bash -c "oryx dockerfile /app | head -n 1 | sed 's/ARG RUNTIME=//' >> /app/oryx-runtime.txt"`;
      await util.execute(command);
      let oryxRuntimeTxtPath = path.join(appSourcePath, "oryx-runtime.txt");
      let runtimeStack = fs.promises.readFile(oryxRuntimeTxtPath, "utf8").then((data) => {
        let lines = data.split("\n");
        return lines[0];
      }).catch((err) => {
        toolHelper2.writeError(err.message);
        throw err;
      });
      fs.unlink(oryxRuntimeTxtPath, (err) => {
        if (err) {
          toolHelper2.writeWarning(`Unable to delete the temporary file "${oryxRuntimeTxtPath}". Error: ${err.message}`);
        }
      });
      return runtimeStack;
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Sets the default builder on the machine to the Oryx++ Builder to prevent an exception from being thrown due
   * to no default builder set.
   */
  async setDefaultBuilder() {
    toolHelper2.writeInfo("Setting the Oryx++ Builder as the default builder via the pack CLI");
    try {
      let command = `config default-builder ${ORYX_BUILDER_IMAGES[0]}`;
      await util.execute(`${PACK_CMD} ${command}`);
    } catch (err) {
      toolHelper2.writeError(err.message);
      throw err;
    }
  }
  /**
   * Installs the pack CLI that will be used to build a runnable application image.
   * For more Information about the pack CLI can be found here: https://buildpacks.io/docs/tools/pack/
   */
  async installPackCliAsync() {
    toolHelper2.writeDebug("Attempting to install the pack CLI");
    try {
      let command = "";
      let commandLine = "";
      if (IS_WINDOWS_AGENT) {
        let packZipDownloadUri = "https://github.com/buildpacks/pack/releases/download/v0.31.0/pack-v0.31.0-windows.zip";
        let packZipDownloadFilePath = path.join(PACK_CMD, "pack-windows.zip");
        command = `New-Item -ItemType Directory -Path ${PACK_CMD} -Force | Out-Null; Invoke-WebRequest -Uri ${packZipDownloadUri} -OutFile ${packZipDownloadFilePath}; Expand-Archive -LiteralPath ${packZipDownloadFilePath} -DestinationPath ${PACK_CMD}; Remove-Item -Path ${packZipDownloadFilePath}`;
        commandLine = "pwsh";
      } else {
        let tgzSuffix = os.platform() == "darwin" ? "macos" : "linux";
        command = `(curl -sSL "https://github.com/buildpacks/pack/releases/download/v0.31.0/pack-v0.31.0-${tgzSuffix}.tgz" | tar -C /usr/local/bin/ --no-same-owner -xzv pack)`;
        commandLine = "bash";
      }
      await util.execute(`${commandLine} -c "${command}"`);
    } catch (err) {
      toolHelper2.writeError(`Unable to install the pack CLI. Error: ${err.message}`);
      throw err;
    }
  }
  /**
   * Enables experimental features for the pack CLI, such as extension support.
   */
  async enablePackCliExperimentalFeaturesAsync() {
    toolHelper2.writeDebug("Attempting to enable experimental features for the pack CLI");
    try {
      let command = `${PACK_CMD} config experimental true`;
      await util.execute(command);
    } catch (err) {
      toolHelper2.writeError(`Unable to enable experimental features for the pack CLI: ${err.message}`);
      throw err;
    }
  }
};

// src/ContainerRegistryHelper.ts
var os2 = __toESM(require("os"));
var toolHelper3 = new GitHubActionsToolHelper();
var util2 = new Utility();
var ContainerRegistryHelper = class {
  /**
   * Authorizes Docker to make calls to the provided Container Registry instance using username and password.
   * @param registryUrl - the name of the Container Registry instance to authenticate calls to
   * @param registryUsername - the username for authentication
   * @param registryPassword - the password for authentication
   */
  async loginContainerRegistryWithUsernamePassword(registryUrl, registryUsername, registryPassword) {
    toolHelper3.writeDebug(`Attempting to log in to Container Registry instance"${registryUrl}" with username and password credentials`);
    try {
      await util2.execute(`docker login --password-stdin --username ${registryUsername} ${registryUrl}`, [], Buffer.from(registryPassword));
    } catch (err) {
      toolHelper3.writeError(`Failed to log in to Container Registry instance "${registryUrl}" with username and password credentials`);
      throw err;
    }
  }
  /**
   * Authorizes Docker to make calls to the provided ACR instance using an access token that is generated via
   * the 'az acr login --expose-token' command.
   * @param acrName - the name of the ACR instance to authenticate calls to.
   */
  async loginAcrWithAccessTokenAsync(acrName) {
    toolHelper3.writeDebug(`Attempting to log in to ACR instance "${acrName}" with access token`);
    try {
      let commandLine = os2.platform() === "win32" ? "pwsh" : "bash";
      await util2.execute(`${commandLine} -c "CA_ADO_TASK_ACR_ACCESS_TOKEN=$(az acr login --name ${acrName} --output json --expose-token --only-show-errors | jq -r '.accessToken'); docker login ${acrName}.azurecr.io -u 00000000-0000-0000-0000-000000000000 -p $CA_ADO_TASK_ACR_ACCESS_TOKEN > /dev/null 2>&1"`);
    } catch (err) {
      toolHelper3.writeError(`Failed to log in to ACR instance "${acrName}" with access token`);
      throw err;
    }
  }
  /**
   * Pushes an image to the Container Registry instance that was previously authenticated against.
   * @param imageToPush - the name of the image to push to the Container Registry instance
   */
  async pushImageToContainerRegistry(imageToPush) {
    toolHelper3.writeDebug(`Attempting to push image "${imageToPush}" to Container Registry`);
    try {
      await util2.execute(`docker push ${imageToPush}`);
    } catch (err) {
      toolHelper3.writeError(`Failed to push image "${imageToPush}" to Container Registry. Error: ${err.message}`);
      throw err;
    }
  }
};

// src/TelemetryHelper.ts
var ORYX_CLI_IMAGE2 = "mcr.microsoft.com/oryx/cli:debian-buster-20230207.2";
var SUCCESSFUL_RESULT = "succeeded";
var FAILED_RESULT = "failed";
var BUILDER_SCENARIO = "used-builder";
var DOCKERFILE_SCENARIO = "used-dockerfile";
var IMAGE_SCENARIO = "used-image";
var util3 = new Utility();
var toolHelper4 = new GitHubActionsToolHelper();
var TelemetryHelper = class {
  constructor(disableTelemetry) {
    this.disableTelemetry = disableTelemetry;
    this.taskStartMilliseconds = Date.now();
  }
  /**
   * Marks that the task was successful in telemetry.
   */
  setSuccessfulResult() {
    this.result = SUCCESSFUL_RESULT;
  }
  /**
   * Marks that the task failed in telemetry.
   */
  setFailedResult(errorMessage) {
    this.result = FAILED_RESULT;
    this.errorMessage = errorMessage;
  }
  /**
   * Marks that the task used the builder scenario.
   */
  setBuilderScenario() {
    this.scenario = BUILDER_SCENARIO;
  }
  /**
   * Marks that the task used the Dockerfile scenario.
   */
  setDockerfileScenario() {
    this.scenario = DOCKERFILE_SCENARIO;
  }
  /**
   * Marks that the task used the previously built image scenario.
   */
  setImageScenario() {
    this.scenario = IMAGE_SCENARIO;
  }
  /**
   * If telemetry is enabled, uses the "oryx telemetry" command to log metadata about this task execution.
   */
  async sendLogs() {
    let taskLengthMilliseconds = Date.now() - this.taskStartMilliseconds;
    if (!this.disableTelemetry) {
      toolHelper4.writeInfo(`Telemetry enabled; logging metadata about task result, length and scenario targeted.`);
      try {
        let resultArg = "";
        if (!util3.isNullOrEmpty(this.result)) {
          resultArg = `--property result=${this.result}`;
        }
        let scenarioArg = "";
        if (!util3.isNullOrEmpty(this.scenario)) {
          scenarioArg = `--property scenario=${this.scenario}`;
        }
        let errorMessageArg = "";
        if (!util3.isNullOrEmpty(this.errorMessage)) {
          errorMessageArg = `--property errorMessage=${this.errorMessage}`;
        }
        let eventName = toolHelper4.getEventName();
        await util3.execute(`docker run --rm ${ORYX_CLI_IMAGE2} /bin/bash -c "oryx telemetry --event-name ${eventName} --processing-time ${taskLengthMilliseconds} ${resultArg} ${scenarioArg} ${errorMessageArg}"`);
      } catch (err) {
        toolHelper4.writeWarning(`Skipping telemetry logging due to the following exception: ${err.message}`);
      }
    }
  }
};

// azurecontainerapps.ts
var buildArgumentRegex = /"[^"]*"|\S+/g;
var buildpackEnvironmentNameRegex = /^"?(BP|ORYX)_[-._a-zA-Z0-9]+"?$/;
var azurecontainerapps = class {
  static async runMain() {
    this.initializeHelpers();
    try {
      this.validateSupportedScenarioArguments();
      await this.setupAzureCli();
      await this.setupResources();
      if (!this.util.isNullOrEmpty(this.registryUrl)) {
        await this.authenticateContainerRegistryAsync();
      }
      if (!this.util.isNullOrEmpty(this.acrName)) {
        await this.authenticateAzureContainerRegistryAsync();
      }
      this.useInternalRegistry = this.util.isNullOrEmpty(this.registryUrl);
      this.shouldCreateOrUpdateContainerAppWithUp = !this.util.isNullOrEmpty(this.appSourcePath) && this.useInternalRegistry;
      if (!this.useInternalRegistry && !this.util.isNullOrEmpty(this.appSourcePath)) {
        await this.buildAndPushImageAsync();
      }
      if (this.util.isNullOrEmpty(this.appSourcePath)) {
        this.setupExistingImageScenario();
      }
      if (this.util.isNullOrEmpty(this.yamlConfigPath)) {
        this.setupContainerAppProperties();
      }
      await this.createOrUpdateContainerApp();
      this.telemetryHelper.setSuccessfulResult();
    } catch (err) {
      this.toolHelper.setFailed(err.message);
      this.telemetryHelper.setFailedResult(err.message);
    } finally {
      await this.telemetryHelper.sendLogs();
    }
  }
  /**
   * Initializes the helpers used by this task.
   * @param disableTelemetry - Whether or not to disable telemetry for this task.
   */
  static initializeHelpers() {
    this.util = new Utility();
    this.toolHelper = new GitHubActionsToolHelper();
    let disableTelemetry = this.toolHelper.getInput("disableTelemetry").toLowerCase() === "true";
    this.buildId = this.toolHelper.getBuildId();
    this.buildNumber = this.toolHelper.getBuildNumber();
    this.telemetryHelper = new TelemetryHelper(disableTelemetry);
    this.appHelper = new ContainerAppHelper(disableTelemetry);
    this.registryHelper = new ContainerRegistryHelper();
  }
  /**
   * Validates the arguments provided to the task for supported scenarios.
   * @throws Error if a valid combination of the support scenario arguments is not provided.
   */
  static validateSupportedScenarioArguments() {
    this.appSourcePath = this.toolHelper.getInput("appSourcePath", false);
    this.acrName = this.toolHelper.getInput("acrName", false);
    this.registryUrl = this.toolHelper.getInput("registryUrl", false);
    this.imageToDeploy = this.toolHelper.getInput("imageToDeploy", false);
    this.yamlConfigPath = this.toolHelper.getInput("yamlConfigPath", false);
    this.imageToBuild = this.toolHelper.getInput("imageToBuild", false);
    this.buildArguments = this.toolHelper.getInput("buildArguments", false);
    if (this.util.isNullOrEmpty(this.appSourcePath) && this.util.isNullOrEmpty(this.imageToDeploy) && this.util.isNullOrEmpty(this.yamlConfigPath)) {
      let requiredArgumentMessage = `One of the following arguments must be provided: 'appSourcePath', 'imageToDeploy', or 'yamlConfigPath'.`;
      this.toolHelper.writeError(requiredArgumentMessage);
      throw Error(requiredArgumentMessage);
    }
    if (!this.util.isNullOrEmpty(this.acrName) && !this.util.isNullOrEmpty(this.registryUrl)) {
      let conflictingArgumentsMessage = `The 'acrName' and 'registryUrl' arguments cannot both be provided.`;
      this.toolHelper.writeError(conflictingArgumentsMessage);
      throw Error(conflictingArgumentsMessage);
    }
    if (!this.util.isNullOrEmpty(this.buildArguments)) {
      const buildArguments = this.buildArguments.match(buildArgumentRegex);
      let invalidBuildArgumentsMessage = `The 'buildArguments' argument must be in the format 'key1=value1 key2=value2'.`;
      const invalidBuildArguments = buildArguments.some((variable) => {
        if (!this.util.isNullOrEmpty(variable)) {
          return variable.indexOf("=") === -1;
        } else {
          return false;
        }
      });
      if (invalidBuildArguments) {
        this.toolHelper.writeError(invalidBuildArgumentsMessage);
        throw Error(invalidBuildArgumentsMessage);
      }
    }
  }
  /**
   * Sets up the Azure CLI to be used for this task by logging in to Azure with the provided service connection and
   * setting the Azure CLI to install missing extensions.
   */
  static async setupAzureCli() {
    await this.util.installAzureCliExtension();
  }
  /**
   * Sets up the resources required to deploy a Container App. This includes the following:
   * - Getting or generating the Container App name
   * - Getting or discovering the location to deploy resources to
   * - Getting or creating the resource group
   * - Getting or creating the Container App Environment
   */
  static async setupResources() {
    this.containerAppName = this.getContainerAppName();
    this.location = await this.getLocation();
    this.resourceGroup = await this.getOrCreateResourceGroup(this.containerAppName, this.location);
    this.containerAppExists = await this.appHelper.doesContainerAppExist(this.containerAppName, this.resourceGroup);
    if (!this.containerAppExists) {
      const disableCreateContainerApp = this.toolHelper.getInput("disableCreateContainerApp").toLowerCase();
      if (!this.containerAppExists && disableCreateContainerApp === "true") {
        this.toolHelper.setFailed(
          "container does not exist or failed to get existing container, exiting job"
        );
        process.exit(1);
        return;
      }
      this.containerAppEnvironment = await this.getOrCreateContainerAppEnvironment(this.containerAppName, this.resourceGroup, this.location);
    }
  }
  /**
   * Gets the name of the Container App to use for the task. If the 'containerAppName' argument is not provided,
   * then a default name will be generated in the form 'gh-action-app-<buildId>-<buildNumber>'.
   * @returns The name of the Container App to use for the task.
   */
  static getContainerAppName() {
    let containerAppName = this.toolHelper.getInput("containerAppName", false);
    if (this.util.isNullOrEmpty(containerAppName)) {
      return this.toolHelper.getDefaultContainerAppName(containerAppName);
    }
    return containerAppName;
  }
  /**
   * Gets the location to deploy resources to. If the 'location' argument is not provided, then the default location
   * for the Container App service will be used.
   * @returns The location to deploy resources to.
   */
  static async getLocation() {
    let location = this.toolHelper.getInput("location", false);
    if (!this.util.isNullOrEmpty(location)) {
      return location;
    }
    let resourceGroup = this.toolHelper.getInput("resourceGroup", false);
    if (!this.util.isNullOrEmpty(resourceGroup)) {
      let containerAppExists = await this.appHelper.doesContainerAppExist(this.containerAppName, resourceGroup);
      if (containerAppExists) {
        var environmentName = await this.appHelper.getExistingContainerAppEnvironmentName(this.containerAppName, resourceGroup);
        var containerAppEnvironmentExistsInResourceGroup = !this.util.isNullOrEmpty(environmentName) ? await this.appHelper.doesContainerAppEnvironmentExist(environmentName, resourceGroup) : false;
        if (containerAppEnvironmentExistsInResourceGroup) {
          location = await this.appHelper.getExistingContainerAppEnvironmentLocation(environmentName, resourceGroup);
          return location;
        }
      }
      let containerAppEnvironment = this.toolHelper.getInput("containerAppEnvironment", false);
      let containerAppEnvironmentExists = !this.util.isNullOrEmpty(containerAppEnvironment) ? await this.appHelper.doesContainerAppEnvironmentExist(containerAppEnvironment, resourceGroup) : false;
      if (containerAppEnvironmentExists) {
        location = await this.appHelper.getExistingContainerAppEnvironmentLocation(containerAppEnvironment, resourceGroup);
        return location;
      }
    }
    location = await this.appHelper.getDefaultContainerAppLocation();
    return location;
  }
  /**
   * Gets the name of the resource group to use for the task. If the 'resourceGroup' argument is not provided,
   * then a default name will be generated in the form '<containerAppName>-rg'. If the generated resource group does
   * not exist, it will be created.
   * @param containerAppName - The name of the Container App to use for the task.
   * @param location - The location to deploy resources to.
   * @returns The name of the resource group to use for the task.
   */
  static async getOrCreateResourceGroup(containerAppName, location) {
    let resourceGroup = this.toolHelper.getInput("resourceGroup", false);
    if (this.util.isNullOrEmpty(resourceGroup)) {
      resourceGroup = `${containerAppName}-rg`;
      this.toolHelper.writeInfo(`Default resource group name: ${resourceGroup}`);
      const resourceGroupExists = await this.appHelper.doesResourceGroupExist(resourceGroup);
      if (!resourceGroupExists) {
        await this.appHelper.createResourceGroup(resourceGroup, location);
      }
    }
    return resourceGroup;
  }
  /**
   * Gets the name of the Container App Environment to use for the task. If the 'containerAppEnvironment' argument
   * is not provided, then the task will attempt to discover an existing Container App Environment in the resource
   * group. If no existing Container App Environment is found, then a default name will be generated in the form
   * '<containerAppName>-env'. If the Container App Environment does not exist, it will be created.
   * @param containerAppName - The name of the Container App to use for the task.
   * @param resourceGroup - The name of the resource group to use for the task.
   * @param location - The location to deploy resources to.
   * @returns The name of the Container App Environment to use for the task.
   */
  static async getOrCreateContainerAppEnvironment(containerAppName, resourceGroup, location) {
    let containerAppEnvironment = this.toolHelper.getInput("containerAppEnvironment", false);
    if (this.util.isNullOrEmpty(containerAppEnvironment)) {
      const existingContainerAppEnvironment = await this.appHelper.getExistingContainerAppEnvironment(resourceGroup);
      if (!this.util.isNullOrEmpty(existingContainerAppEnvironment)) {
        this.toolHelper.writeInfo(`Existing Container App environment found in resource group: ${existingContainerAppEnvironment}`);
        return existingContainerAppEnvironment;
      }
    }
    if (this.util.isNullOrEmpty(containerAppEnvironment)) {
      containerAppEnvironment = `${containerAppName}-env`;
      this.toolHelper.writeInfo(`Default Container App environment name: ${containerAppEnvironment}`);
    }
    const containerAppEnvironmentExists = await this.appHelper.doesContainerAppEnvironmentExist(containerAppEnvironment, resourceGroup);
    if (!containerAppEnvironmentExists) {
      await this.appHelper.createContainerAppEnvironment(containerAppEnvironment, resourceGroup, location);
    }
    return containerAppEnvironment;
  }
  /**
   * Authenticates calls to the provided Azure Container Registry.
   */
  static async authenticateAzureContainerRegistryAsync() {
    this.registryUsername = this.toolHelper.getInput("acrUsername", false);
    this.registryPassword = this.toolHelper.getInput("acrPassword", false);
    this.registryUrl = `${this.acrName}.azurecr.io`;
    if (!this.util.isNullOrEmpty(this.registryUsername) && !this.util.isNullOrEmpty(this.registryPassword)) {
      this.toolHelper.writeInfo(`Logging in to ACR instance "${this.acrName}" with username and password credentials`);
      await this.registryHelper.loginContainerRegistryWithUsernamePassword(this.registryUrl, this.registryUsername, this.registryPassword);
    } else {
      this.toolHelper.writeInfo(`No ACR credentials provided; attempting to log in to ACR instance "${this.acrName}" with access token`);
      await this.registryHelper.loginAcrWithAccessTokenAsync(this.acrName);
    }
  }
  /**
   * Authenticates calls to the provided Container Registry.
   */
  static async authenticateContainerRegistryAsync() {
    this.registryUsername = this.toolHelper.getInput("registryUsername", false);
    this.registryPassword = this.toolHelper.getInput("registryPassword", false);
    if (!this.util.isNullOrEmpty(this.registryUsername) && !this.util.isNullOrEmpty(this.registryPassword)) {
      this.toolHelper.writeInfo(`Logging in to Container Registry "${this.registryUrl}" with username and password credentials`);
      await this.registryHelper.loginContainerRegistryWithUsernamePassword(this.registryUrl, this.registryUsername, this.registryPassword);
    }
  }
  /**
   * Sets up the scenario where an existing image is used for the Container App.
   */
  static setupExistingImageScenario() {
    this.telemetryHelper.setImageScenario();
  }
  /**
   * Builds a runnable application image using a Dockerfile or the builder and pushes it to the Container Registry.
   */
  static async buildAndPushImageAsync() {
    this.imageToBuild = this.toolHelper.getInput("imageToBuild", false);
    if (this.util.isNullOrEmpty(this.imageToBuild)) {
      const imageRepository = this.toolHelper.getDefaultImageRepository();
      this.imageToBuild = `${this.registryUrl}/${imageRepository}:${this.buildId}.${this.buildNumber}`;
      this.toolHelper.writeInfo(`Default image to build: ${this.imageToBuild}`);
    }
    if (this.util.isNullOrEmpty(this.imageToDeploy)) {
      this.imageToDeploy = this.imageToBuild;
      this.toolHelper.writeInfo(`Default image to deploy: ${this.imageToDeploy}`);
    }
    let buildArguments = [];
    if (!this.util.isNullOrEmpty(this.buildArguments)) {
      this.buildArguments.match(buildArgumentRegex).forEach((buildArg) => {
        buildArguments.push(buildArg);
      });
    }
    let dockerfilePath = this.toolHelper.getInput("dockerfilePath", false);
    if (this.util.isNullOrEmpty(dockerfilePath)) {
      this.toolHelper.writeInfo(`No Dockerfile path provided; checking for Dockerfile at root of application source.`);
      const rootDockerfilePath = path2.join(this.appSourcePath, "Dockerfile");
      if (fs2.existsSync(rootDockerfilePath)) {
        this.toolHelper.writeInfo(`Dockerfile found at root of application source.`);
        dockerfilePath = rootDockerfilePath;
      } else {
        await this.buildImageFromBuilderAsync(this.appSourcePath, this.imageToBuild, buildArguments);
      }
    } else {
      dockerfilePath = path2.join(this.appSourcePath, dockerfilePath);
    }
    if (!this.util.isNullOrEmpty(dockerfilePath)) {
      await this.buildImageFromDockerfile(this.appSourcePath, dockerfilePath, this.imageToBuild, buildArguments);
    }
    await this.registryHelper.pushImageToContainerRegistry(this.imageToBuild);
  }
  /**
   * Builds a runnable application image using the builder.
   * @param appSourcePath - The path to the application source code.
   * @param imageToBuild - The name of the image to build.
   * @param buildArguments - The build arguments to pass to the pack command via environment variables.
   */
  static async buildImageFromBuilderAsync(appSourcePath, imageToBuild, buildArguments) {
    if (buildArguments.length > 0) {
      buildArguments.forEach((buildArg) => {
        const nameAndValue = buildArg.split("=");
        const isNameValid = nameAndValue[0].match(buildpackEnvironmentNameRegex);
        if (!isNameValid) {
          const invalidBuildArgumentsMessage = `Build environment variable name must consist of alphanumeric characters, numbers, '_', '.' or '-', start with 'BP_' or 'ORYX_'.`;
          this.toolHelper.writeError(invalidBuildArgumentsMessage);
          throw Error(invalidBuildArgumentsMessage);
        }
      });
    }
    await this.appHelper.installPackCliAsync();
    this.toolHelper.writeInfo(`Successfully installed the pack CLI.`);
    await this.appHelper.enablePackCliExperimentalFeaturesAsync();
    this.toolHelper.writeInfo(`Successfully enabled experimental features for the pack CLI.`);
    let environmentVariables = [];
    const runtimeStack = this.toolHelper.getInput("runtimeStack", false);
    if (!this.util.isNullOrEmpty(runtimeStack)) {
      const runtimeStackSplit = runtimeStack.split(":");
      const platformName = runtimeStackSplit[0] == "dotnetcore" ? "dotnet" : runtimeStackSplit[0];
      const platformVersion = runtimeStackSplit[1];
      environmentVariables.push(`ORYX_PLATFORM_NAME=${platformName}`);
      environmentVariables.push(`ORYX_PLATFORM_VERSION=${platformVersion}`);
    }
    const builderStack = this.toolHelper.getInput("builderStack", false);
    if (!this.util.isNullOrEmpty(this.targetPort)) {
      environmentVariables.push(`ORYX_RUNTIME_PORT=${this.targetPort}`);
    }
    if (buildArguments.length > 0) {
      buildArguments.forEach((buildArg) => {
        environmentVariables.push(buildArg);
      });
    }
    this.toolHelper.writeInfo(`Building image "${imageToBuild}" using the Oryx++ Builder`);
    await this.appHelper.setDefaultBuilder();
    await this.appHelper.createRunnableAppImage(imageToBuild, appSourcePath, environmentVariables, builderStack);
    this.telemetryHelper.setBuilderScenario();
  }
  /**
   * Builds a runnable application image using a provided or discovered Dockerfile.
   * @param appSourcePath - The path to the application source code.
   * @param dockerfilePath - The path to the Dockerfile to build.
   * @param imageToBuild - The name of the image to build.
   * @param buildArguments - The build arguments to pass to the docker build command.
   */
  static async buildImageFromDockerfile(appSourcePath, dockerfilePath, imageToBuild, buildArguments) {
    this.toolHelper.writeInfo(`Building image "${imageToBuild}" using the provided Dockerfile`);
    await this.appHelper.createRunnableAppImageFromDockerfile(imageToBuild, appSourcePath, dockerfilePath, buildArguments);
    this.telemetryHelper.setDockerfileScenario();
  }
  /**
   * Sets up the Container App properties that will be passed through to the Azure CLI when a YAML configuration
   * file is not provided.
   */
  static setupContainerAppProperties() {
    this.commandLineArgs = [];
    this.ingress = this.toolHelper.getInput("ingress", false);
    this.targetPort = this.toolHelper.getInput("targetPort", false);
    this.noIngressUpdate = this.containerAppExists && this.util.isNullOrEmpty(this.targetPort) && (this.util.isNullOrEmpty(this.ingress) || this.ingress == "disabled");
    if (!this.util.isNullOrEmpty(this.registryUrl) && !this.util.isNullOrEmpty(this.registryUsername) && !this.util.isNullOrEmpty(this.registryPassword) && (!this.containerAppExists || this.containerAppExists && !this.noIngressUpdate)) {
      this.adminCredentialsProvided = true;
      this.commandLineArgs.push(
        `--registry-server ${this.registryUrl}`,
        `--registry-username ${this.registryUsername}`,
        `--registry-password ${this.registryPassword}`
      );
    }
    if (!this.containerAppExists) {
      this.ingressEnabled = true;
      if (this.util.isNullOrEmpty(this.ingress)) {
        this.ingress = "external";
        this.toolHelper.writeInfo(`Default ingress value: ${this.ingress}`);
      }
      if (this.ingress == "disabled") {
        this.ingressEnabled = false;
        this.toolHelper.writeInfo(`Ingress is disabled for this Container App.`);
      }
      if (this.ingressEnabled) {
        this.targetPort = this.toolHelper.getInput("targetPort", false);
        if (this.util.isNullOrEmpty(this.targetPort)) {
          this.targetPort = "80";
          this.toolHelper.writeInfo(`Default target port: ${this.targetPort}`);
        }
        this.commandLineArgs.push(`--ingress ${this.ingress}`);
        this.commandLineArgs.push(`--target-port ${this.targetPort}`);
      }
    }
    const environmentVariables = this.toolHelper.getInput("environmentVariables", false);
    const isCappUpdateCommandUsed = this.noIngressUpdate || !this.noIngressUpdate && !this.adminCredentialsProvided;
    if (!this.util.isNullOrEmpty(environmentVariables)) {
      if (isCappUpdateCommandUsed) {
        this.commandLineArgs.push(`--replace-env-vars ${environmentVariables}`);
      } else {
        this.commandLineArgs.push(`--env-vars ${environmentVariables}`);
      }
    }
    if (!this.util.isNullOrEmpty(this.imageToDeploy)) {
      this.commandLineArgs.push(`-i ${this.imageToDeploy}`);
    } else if (this.shouldCreateOrUpdateContainerAppWithUp) {
      this.commandLineArgs.push(`--source ${this.appSourcePath}`);
      this.commandLineArgs.push(`-l ${this.location}`);
    }
  }
  /**
   * Creates or updates the Container App.
   */
  static async createOrUpdateContainerApp() {
    if (!this.containerAppExists) {
      if (!this.util.isNullOrEmpty(this.yamlConfigPath)) {
        await this.appHelper.createContainerAppFromYaml(this.containerAppName, this.resourceGroup, this.yamlConfigPath);
      } else if (this.shouldCreateOrUpdateContainerAppWithUp) {
        await this.appHelper.createOrUpdateContainerAppWithUp(this.containerAppName, this.resourceGroup, this.commandLineArgs);
      } else {
        await this.appHelper.createContainerApp(this.containerAppName, this.resourceGroup, this.containerAppEnvironment, this.commandLineArgs);
      }
      return;
    }
    if (!this.util.isNullOrEmpty(this.yamlConfigPath)) {
      await this.appHelper.updateContainerAppFromYaml(this.containerAppName, this.resourceGroup, this.yamlConfigPath);
      return;
    }
    if (this.noIngressUpdate && !this.shouldCreateOrUpdateContainerAppWithUp) {
      if (!this.util.isNullOrEmpty(this.registryUrl) && !this.util.isNullOrEmpty(this.registryUsername) && !this.util.isNullOrEmpty(this.registryPassword)) {
        await this.appHelper.updateContainerAppRegistryDetails(this.containerAppName, this.resourceGroup, this.registryUrl, this.registryUsername, this.registryPassword);
      }
      await this.appHelper.updateContainerApp(this.containerAppName, this.resourceGroup, this.commandLineArgs);
    } else if (this.shouldCreateOrUpdateContainerAppWithUp) {
      await this.appHelper.createOrUpdateContainerAppWithUp(this.containerAppName, this.resourceGroup, this.commandLineArgs);
    } else if (this.adminCredentialsProvided && !this.noIngressUpdate) {
      await this.appHelper.updateContainerAppWithUp(this.containerAppName, this.resourceGroup, this.commandLineArgs, this.ingress, this.targetPort);
    } else {
      await this.appHelper.updateContainerApp(this.containerAppName, this.resourceGroup, this.commandLineArgs);
      await this.appHelper.updateContainerAppIngress(this.containerAppName, this.resourceGroup, this.ingress, this.targetPort);
    }
    if (this.ingress == "disabled") {
      await this.appHelper.disableContainerAppIngress(this.containerAppName, this.resourceGroup);
    }
  }
};
azurecontainerapps.runMain();
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  azurecontainerapps
});
