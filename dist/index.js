'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var fs = _interopDefault(require('fs'));
var path = _interopDefault(require('path'));
var zlib = _interopDefault(require('zlib'));

function createCommonjsModule(fn, module) {
	return module = { exports: {} }, fn(module, module.exports), module.exports;
}

var crypt = createCommonjsModule(function (module) {
(function() {
  var base64map
      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',

  crypt = {
    // Bit-wise rotation left
    rotl: function(n, b) {
      return (n << b) | (n >>> (32 - b));
    },

    // Bit-wise rotation right
    rotr: function(n, b) {
      return (n << (32 - b)) | (n >>> b);
    },

    // Swap big-endian to little-endian and vice versa
    endian: function(n) {
      // If number given, swap endian
      if (n.constructor == Number) {
        return crypt.rotl(n, 8) & 0x00FF00FF | crypt.rotl(n, 24) & 0xFF00FF00;
      }

      // Else, assume array and swap all items
      for (var i = 0; i < n.length; i++)
        n[i] = crypt.endian(n[i]);
      return n;
    },

    // Generate an array of any length of random bytes
    randomBytes: function(n) {
      for (var bytes = []; n > 0; n--)
        bytes.push(Math.floor(Math.random() * 256));
      return bytes;
    },

    // Convert a byte array to big-endian 32-bit words
    bytesToWords: function(bytes) {
      for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
        words[b >>> 5] |= bytes[i] << (24 - b % 32);
      return words;
    },

    // Convert big-endian 32-bit words to a byte array
    wordsToBytes: function(words) {
      for (var bytes = [], b = 0; b < words.length * 32; b += 8)
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a hex string
    bytesToHex: function(bytes) {
      for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
      }
      return hex.join('');
    },

    // Convert a hex string to a byte array
    hexToBytes: function(hex) {
      for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
      return bytes;
    },

    // Convert a byte array to a base-64 string
    bytesToBase64: function(bytes) {
      for (var base64 = [], i = 0; i < bytes.length; i += 3) {
        var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        for (var j = 0; j < 4; j++)
          if (i * 8 + j * 6 <= bytes.length * 8)
            base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
          else
            base64.push('=');
      }
      return base64.join('');
    },

    // Convert a base-64 string to a byte array
    base64ToBytes: function(base64) {
      // Remove non-base-64 characters
      base64 = base64.replace(/[^A-Z0-9+\/]/ig, '');

      for (var bytes = [], i = 0, imod4 = 0; i < base64.length;
          imod4 = ++i % 4) {
        if (imod4 == 0) continue;
        bytes.push(((base64map.indexOf(base64.charAt(i - 1))
            & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2))
            | (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
      }
      return bytes;
    }
  };

  module.exports = crypt;
})();
});

var charenc = {
  // UTF-8 encoding
  utf8: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      return charenc.bin.stringToBytes(unescape(encodeURIComponent(str)));
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      return decodeURIComponent(escape(charenc.bin.bytesToString(bytes)));
    }
  },

  // Binary encoding
  bin: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      for (var bytes = [], i = 0; i < str.length; i++)
        bytes.push(str.charCodeAt(i) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      for (var str = [], i = 0; i < bytes.length; i++)
        str.push(String.fromCharCode(bytes[i]));
      return str.join('');
    }
  }
};

var charenc_1 = charenc;

var sha1 = createCommonjsModule(function (module) {
(function() {
  var crypt$1 = crypt,
      utf8 = charenc_1.utf8,
      bin = charenc_1.bin,

  // The core
  sha1 = function (message) {
    // Convert to byte array
    if (message.constructor == String)
      message = utf8.stringToBytes(message);
    else if (typeof Buffer !== 'undefined' && typeof Buffer.isBuffer == 'function' && Buffer.isBuffer(message))
      message = Array.prototype.slice.call(message, 0);
    else if (!Array.isArray(message))
      message = message.toString();

    // otherwise assume byte array

    var m  = crypt$1.bytesToWords(message),
        l  = message.length * 8,
        w  = [],
        H0 =  1732584193,
        H1 = -271733879,
        H2 = -1732584194,
        H3 =  271733878,
        H4 = -1009589776;

    // Padding
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >>> 9) << 4) + 15] = l;

    for (var i = 0; i < m.length; i += 16) {
      var a = H0,
          b = H1,
          c = H2,
          d = H3,
          e = H4;

      for (var j = 0; j < 80; j++) {

        if (j < 16)
          w[j] = m[i + j];
        else {
          var n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
          w[j] = (n << 1) | (n >>> 31);
        }

        var t = ((H0 << 5) | (H0 >>> 27)) + H4 + (w[j] >>> 0) + (
                j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 :
                j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 :
                j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 :
                         (H1 ^ H2 ^ H3) - 899497514);

        H4 = H3;
        H3 = H2;
        H2 = (H1 << 30) | (H1 >>> 2);
        H1 = H0;
        H0 = t;
      }

      H0 += a;
      H1 += b;
      H2 += c;
      H3 += d;
      H4 += e;
    }

    return [H0, H1, H2, H3, H4];
  },

  // Public API
  api = function (message, options) {
    var digestbytes = crypt$1.wordsToBytes(sha1(message));
    return options && options.asBytes ? digestbytes :
        options && options.asString ? bin.bytesToString(digestbytes) :
        crypt$1.bytesToHex(digestbytes);
  };

  api._blocksize = 16;
  api._digestsize = 20;

  module.exports = api;
})();
});

/**
 * @description The default options for the cache
 */
const defaultCacheOptions = {
  enabled: true,
  enable: true,
  type: 'lru-cache',
  lruOptions: {
    max: 100000,
    length: function (n, key) {
      return n * 2 + key.length;
    },
    maxAge: 1000 * 60 * 60
  },
  redisOptions: {
    ttl: 86400,
    // 24 hours
    host: process.env.REDIS_HOST
  }
};
function Cache(customCacheOptions = defaultCacheOptions) {
  let lruCache = null;
  let redisCache = null;
  const cacheOptions = { ...defaultCacheOptions,
    ...customCacheOptions,
    lruOptions: { ...defaultCacheOptions.lruOptions,
      ...customCacheOptions.lruOptions
    },
    redisOptions: { ...defaultCacheOptions.redisOptions,
      ...customCacheOptions.redisOptions,
      dropBufferSupport: false
    }
  };

  if (cacheOptions.type === 'lru-cache') {
    const LRU = require('lru-cache');

    lruCache = new LRU(cacheOptions.lruOptions);
  } else if (cacheOptions.type === 'redis') {
    const Redis = require('ioredis');

    redisCache = new Redis(cacheOptions.redisOptions);
  }

  return {
    /**
     * @description Get the cache key for a table, tile data and where statement of the filters
     *
     * @param {string} table The cache table name
     * @param {number} z The tile zoom level
     * @param {number} x The tile x position
     * @param {number} y The tile y position
     * @param {string[]} filters The where statement
     * @returns The cache key
     */
    getCacheKey: (table, z, x, y, filters) => {
      if (!cacheOptions.enabled || !cacheOptions.enable) {
        return null;
      }

      const where = sha1(filters.sort((a, b) => a > b ? 1 : a < b ? -1 : 0).join('-'));
      return `${table}-${z}-${x}-${y}-${where}`;
    },

    /**
     * @description Get the cache value of a cache key
     *
     * @param {string} key The cache key
     * @returns The cache value or null if not found or disabled
     */
    getCacheValue: async key => {
      if (!cacheOptions.enabled || !cacheOptions.enable) {
        return null;
      }

      if (cacheOptions.type === 'lru-cache') {
        return lruCache.get(key);
      }

      if (cacheOptions.type === 'redis') {
        return await redisCache.getBuffer(key);
      } // Invalid type


      return null;
    },

    /**
     * @description Set the cache value for a cache key
     *
     * @param {string} key The cache key
     * @param {any} value The cache value
     * @param {number} zoomLevel The zoom level requested
     * @param {number | TTtl} ttl The time to leave of the cache
     */
    setCacheValue: async (key, value, ttl) => {
      if (!cacheOptions.enabled || !cacheOptions.enable) {
        return null;
      }

      if (cacheOptions.type === 'lru-cache') {
        lruCache.set(key, value);
      } else if (cacheOptions.type === 'redis') {
        if (!!ttl) {
          await redisCache.set(key, value, 'EX', ttl);
        } else {
          await redisCache.set(key, value);
        }
      }
    },

    /**
     * @description Get the cache TTL from the zoom level and request cache TTL or config cache TTL
     *
     * @param {number} zoomLevel The zoom level requested
     * @param {number | TTtl} ttl The time to leave of the cache
     */
    getCacheTtl: (zoomLevel, ttl) => {
      if (!cacheOptions.enabled || !cacheOptions.enable || cacheOptions.type !== 'redis') {
        return 0;
      }

      const requestTtl = ttl || cacheOptions.redisOptions.ttl;

      if (!!requestTtl) {
        return !isNaN(requestTtl) ? requestTtl : requestTtl(zoomLevel);
      }

      return 0;
    }
  };
}

/**
 * Creates an SQL fragment of the dynamic attributes to an sql select statement
 */
const attributesToSelect = attributes => attributes.length > 0 ? `, ${attributes.join(', ')}` : '';
/**
 * Creates an SQL fragmemt which selects the first value of an attribute using the FIRST aggregate function
 */

const attributesFirstToSelect = attributes => attributes.length > 0 ? `${attributes.map(attribute => `FIRST(${attribute}) as ${attribute}`).join(', ')},` : '';
/**
 * Creates an SQL fragment that selects the dynamic attributes to be used by each zoom level query
 */

const attributesToArray = attributes => attributes.length > 0 ? ', ' + attributes.map(attribute => `'${attribute}', ${attribute}`).join(', ') : '';

/**
 * @description The default base query builder
 */
const defaultGetBaseQuery = ({
  x,
  y,
  z,
  table,
  geometry,
  maxZoomLevel,
  attributes,
  query
}) => `
SELECT
  ${geometry} AS center,
  1 AS size,
  0 AS clusterNo,
  ${maxZoomLevel + 1} AS expansionZoom${attributes}
FROM ${table}
WHERE 
	ST_Intersects(TileBBox(${z}, ${x}, ${y}, 3857), ST_Transform(${geometry}, 3857))
	${query.length > 0 ? `AND ${query.join(' AND ')}` : ''}
`;

/**
 * @description The default level query builder
 */
const defaultGetLevelClusterQuery = ({
  parentTable,
  zoomLevel,
  radius,
  attributes,
  zoomToDistance
}) => `
SELECT
  center,
  expansionZoom,
  clusterNo AS previousClusterNo,
  size,
  ST_ClusterDBSCAN(center, ${zoomToDistance(zoomLevel, radius)}, 1) over () as clusters${attributes}
FROM ${parentTable}
`;
/**
 * @description The default level query builder
 */

const defaultGetLevelGroupQuery = ({
  zoomLevel,
  attributes
}) => `
SELECT
  SUM(size) as size,
  clusters AS clusterNo,
  (
    CASE COUNT(previousClusterNo) 
      WHEN 1 THEN FIRST(expansionZoom) 
      ELSE ${zoomLevel + 1} END
  ) AS expansionZoom, ${attributes}
  ST_Centroid(ST_Collect(center)) as center
FROM clustered_${zoomLevel}
GROUP BY clusters
`;

/**
 * @description The default tile query builder
 */
const defaultGetTileQuery = ({
  x,
  y,
  z,
  table,
  geometry,
  extent,
  bufferSize,
  attributes
}) => `
SELECT
  ST_AsMVTGeom(ST_Transform(${geometry}, 3857), TileBBox(${z}, ${x}, ${y}, 3857), ${extent}, ${bufferSize}, false) AS geom,
  jsonb_build_object(
    'count', size, 
    'expansionZoom', expansionZoom, 
    'lng', ST_X(ST_Transform(${geometry}, 4326)), 
    'lat', ST_Y(ST_Transform(${geometry}, 4326))${attributes}, 
    'duplicates', COUNT(*) OVER (PARTITION BY ${geometry})
  ) AS attributes
FROM ${table}
`;

/**
 * @description The dafault implementation of zoom to distance
 */
const defaultZoomToDistance = (zoomLevel, radius = 15) => radius / Math.pow(2, zoomLevel);

function createQueryForTile({
  z,
  x,
  y,
  maxZoomLevel,
  table,
  geometry,
  sourceLayer,
  radius,
  extent,
  bufferSize,
  attributes,
  query,
  debug,
  zoomToDistance = defaultZoomToDistance,
  getBaseQuery = defaultGetBaseQuery,
  getTileQuery = defaultGetTileQuery,
  getLevelClusterQuery = defaultGetLevelClusterQuery,
  getLevelGroupQuery = defaultGetLevelGroupQuery
}) {
  const queryParts = [];
  queryParts.push(`WITH base_query AS (${getBaseQuery({
    x,
    y,
    z,
    table,
    geometry,
    maxZoomLevel,
    attributes: attributesToSelect(attributes),
    query
  })})`);
  let parentTable = 'base_query';

  if (z <= maxZoomLevel) {
    for (let i = maxZoomLevel; i >= z; --i) {
      queryParts.push(`clustered_${i} AS (${getLevelClusterQuery({
        parentTable,
        zoomLevel: i,
        radius,
        attributes: attributesToSelect(attributes),
        zoomToDistance
      })})`);
      queryParts.push(`grouped_clusters_${i} AS (${getLevelGroupQuery({
        zoomLevel: i,
        attributes: attributesFirstToSelect(attributes)
      })})`);
      parentTable = `grouped_clusters_${i}`;
    }
  }

  queryParts.push(`tile AS (${getTileQuery({
    x,
    y,
    z,
    table: parentTable,
    geometry: 'center',
    extent,
    bufferSize,
    attributes: attributesToArray(attributes)
  })})`);
  const sql = `${queryParts.join(',\n')}\nSELECT ST_AsMVT(tile, '${sourceLayer}', ${extent}, 'geom') AS mvt FROM tile`;
  debug && console.log(sql);
  return sql;
}

async function createSupportingSQLFunctions(pool) {
  console.log('attempting to create supporting SQL functions');

  try {
    await pool.query(fs.readFileSync(path.join(__dirname, '../sql/First.sql'), 'utf-8'));
  } catch (e) {
    console.log('failure in creating First SQL function');
  }

  try {
    await pool.query(fs.readFileSync(path.join(__dirname, '../sql/TileBBox.sql'), 'utf-8'));
  } catch (e) {
    console.log('failure in creating TileBBox SQL function');
  }

  try {
    await pool.query(fs.readFileSync(path.join(__dirname, '../sql/TileDoubleBBox.sql'), 'utf-8'));
  } catch (e) {
    console.log('failure in creating TileDoubleBBox SQL function');
  }
}

function zip(data) {
  return new Promise((resolve, reject) => {
    zlib.gzip(data, (err, result) => {
      if (err) {
        return reject(err);
      }

      resolve(result);
    });
  });
}

async function TileServer({
  maxZoomLevel = 12,
  cacheOptions = defaultCacheOptions,
  pgPoolOptions = {},
  filtersToWhere = null,
  attributes = [],
  debug = false
}) {
  const {
    Pool
  } = require('pg');

  const pool = new Pool({
    max: 100,
    ...pgPoolOptions
  });
  pool.on('error', err => {
    debug && console.error('Unexpected error on idle client', err);
    process.exit(-1);
  });
  const cache = Cache(cacheOptions);
  await createSupportingSQLFunctions(pool);
  return async ({
    z,
    x,
    y,
    table = 'public.points',
    geometry = 'wkb_geometry',
    sourceLayer = 'points',
    maxZoomLevel: requestMaxZoomLevel = undefined,
    cacheTtl = undefined,
    radius = 15,
    extent = 4096,
    bufferSize = 256,
    queryParams = {},
    id = '',
    zoomToDistance = defaultZoomToDistance,
    getBaseQuery = defaultGetBaseQuery
  }) => {
    try {
      const filtersQuery = !!filtersToWhere ? filtersToWhere(queryParams) : [];
      debug && console.time('query' + id);
      const cacheKey = cache.getCacheKey(table, z, x, y, filtersQuery);

      try {
        const value = await cache.getCacheValue(cacheKey);

        if (value) {
          return value;
        }
      } catch (e) {
        // In case the cache get fail, we continue to generate the tile
        debug && console.log({
          e
        });
      }

      let query;
      z = parseInt(`${z}`, 10);

      if (isNaN(z)) {
        throw new Error('Invalid zoom level');
      }

      x = parseInt(`${x}`, 10);
      y = parseInt(`${y}`, 10);

      if (isNaN(x) || isNaN(y)) {
        throw new Error('Invalid tile coordinates');
      }

      try {
        query = createQueryForTile({
          z,
          x,
          y,
          maxZoomLevel: requestMaxZoomLevel || maxZoomLevel,
          table,
          geometry,
          radius,
          sourceLayer,
          extent,
          bufferSize,
          attributes,
          query: filtersQuery,
          debug,
          zoomToDistance,
          getBaseQuery
        });
        const result = await pool.query(query);
        debug && console.timeEnd('query' + id);
        debug && console.time('gzip' + id);
        const tile = await zip(result.rows[0].mvt);
        debug && console.timeEnd('gzip' + id);

        try {
          await cache.setCacheValue(cacheKey, tile, (await cache.getCacheTtl(z, cacheTtl)));
        } catch (e) {
          // In case the cache set fail, we should return the generated tile
          debug && console.log({
            e
          });
        }

        return tile;
      } catch (e) {
        debug && console.log(query);
        debug && console.log({
          e
        });
      }
    } catch (e) {
      debug && console.log('e in connect', e);
    }
  };
}

exports.TileServer = TileServer;
