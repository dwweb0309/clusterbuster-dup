import { RedisOptions } from 'ioredis';
import { Options } from 'lru-cache';
import { PoolConfig } from 'pg';

/**
 * @description Input interface for the base query builder
 */
interface IBaseQueryInput {
    x: number;
    y: number;
    z: number;
    table: string;
    geometry: string;
    maxZoomLevel: number;
    attributes: string;
    query: string[];
}
/**
 * @description The base query builder callback definition
 */
declare type GetBaseQuery = (input: IBaseQueryInput) => string;

declare type ZoomToDistance = (zoomLevel: number, radius: number) => number;

/**
 * @description Input interface for the level cluster query builder
 */
interface ILevelClusterQuery {
    parentTable: string;
    zoomLevel: number;
    radius: number;
    attributes: string;
    zoomToDistance: ZoomToDistance;
}
/**
 * @description The level cluster query builder callback definition
 */
declare type GetLevelClusterQuery = (input: ILevelClusterQuery) => string;
/**
 * @description Input interface for the level group query builder
 */
interface ILevelGroupQuery {
    zoomLevel: number;
    attributes: string;
}
/**
 * @description The level group query builder callback definition
 */
declare type GetLevelGroupQuery = (input: ILevelGroupQuery) => string;

/**
 * @description Input interface for the tile query builder
 */
interface ITileQuery {
    x: number;
    y: number;
    z: number;
    table: string;
    geometry: string;
    extent: number;
    bufferSize: number;
    attributes: string;
}
/**
 * @description The tile query builder callback definition
 */
declare type GetTileQuery = (input: ITileQuery) => string;

interface TileCacheOptions {
    /**
     * @description Flag which indicate if the cache should be enabled. Default is true.
     */
    enabled?: boolean;
    /**
     * @deprecated replaced by {enabled}
     */
    enable?: boolean;
    /**
     * @description The type of the cache. Default is lru-cache
     */
    type?: 'lru-cache' | 'redis';
    /**
     * @description LRU cache options
     */
    lruOptions?: Options;
    /**
     * @description Redis connect options
     */
    redisOptions?: RedisOptions & {
        /**
         * @description The time to live in seconds. Default is 86400 (1 day)
         */
        ttl?: number;
    };
}

/**
 * The specification of the tile request
 */
interface TileRequest {
    /**
     * @description The zoom level ranging from 0 - 20
     */
    z: number;
    /**
     * @description The tile x offset on Mercator Projection
     */
    x: number;
    /**
     * @description The tile y offset on Mercator Projection
     */
    y: number;
}

declare type TTtl = (zoomLevel: number) => number;

/**
 * @description The required input values for the tile renderer
 */
interface TileInput<T> extends TileRequest {
    /**
     * @description The name of the table, default is "public.points"
     */
    table?: string;
    /**
     * @description The geometry column name, default is "wkb_geometry". This column should be of type Geometry in PostGIS
     */
    geometry?: string;
    /**
     * @description The MVT source layer on which the points are rendered, default is points
     */
    sourceLayer?: string;
    /**
     * @description The cluster radius in pixels. Default is 15
     */
    radius?: number;
    /**
     * @description The tile extent is the grid dimension value as specified by ST_AsMVT. The default is 4096.
     * @see https://postgis.net/docs/ST_AsMVT.html
     */
    extent?: number;
    /**
     * @description The buffer around the tile extent in the number of grid cells as specified by ST_AsMVT. The default is 256.
     * @see https://postgis.net/docs/ST_AsMVT.html
     */
    bufferSize?: number;
    /**
     * @description The query parameters used to filter
     */
    queryParams?: T | {};
    /**
     * @description Unique ID of the request, default is an empty string
     */
    id?: string;
    /**
     * @description Mapping function from zoomLevel to eps distance in ST_ClusterDBSCAN
     * Default is `(zoomLevel: number, radius: number = 15) => radius / Math.pow(2, zoomLevel);`
     * and should be sufficient for most scenario's. Override this function can be useful to tweak
     * cluster radius for specific zoom levels.
     *
     */
    zoomToDistance?: ZoomToDistance;
    /**
     * @description Function which create the based query with applied filters
     * Default is using the table name to select from and add the intersect within the BBox of the tiles,
     * also add the filters to where in the query
     * Be aware, if you overwrite this you need to make sure the result return the following columns:
     * - "geometry" AS center
     * - 1 AS size
     * - 0 AS clusterNo
     * - "maxZoomLevel + 1" AS expansionZoom
     * - all the attibutes from the list
     */
    getBaseQuery?: GetBaseQuery;
    /**
     * @description The highest zoom level at which data is clustered.
     * Any tile requests at zoom levels higher than this will return individual points only.
     * This will overwrite the `maxZoomLevel` provided to the server initialization
     */
    maxZoomLevel?: number;
    /**
     * @description Optional cache TTL to overwrite the server cache configuration
     */
    cacheTtl?: number | TTtl;
}

/**
 * @description This function creates the MVT tiles from the appropriate TileInput
 */
declare type TileRenderer<T> = (args: TileInput<T>) => Promise<ArrayBuffer>;

/**
 * @description Configuration options for the tile server
 */
interface TileServerConfig<T> {
    /**
     * @description The highest zoom level at which data is clustered.
     * Any tile requests at zoom levels higher than this will return individual points only.
     */
    maxZoomLevel?: number;
    /**
     * @description The tile resolution in pixels, default is 512, but try 256 if you
     * are unsure what your mapping front-end library uses
     * @deprecated This is ignored and will be removed in future releases
     */
    resolution?: number;
    /**
     * @description LRU tile cache options, each tile request is stored in this cache.
     * clusterbuster tries to provide sane defaults
     */
    cacheOptions?: TileCacheOptions;
    /**
     * @description Configuration options for the postgres connection pool
     * clusterbuster tries to provide sane defaults
     */
    pgPoolOptions?: PoolConfig;
    /**
     * @description Optional callback to map the filters to where conditions in PostGreSQL
     */
    filtersToWhere?: (queryParams: T | {}) => string[];
    /**
     * @description Attributes to select from the table
     */
    attributes: string[];
    /**
     * @description Show debug logging, default false
     */
    debug?: boolean;
}

declare function TileServer<T>({ maxZoomLevel, cacheOptions, pgPoolOptions, filtersToWhere, attributes, debug, }: TileServerConfig<T>): Promise<TileRenderer<T>>;

export { GetBaseQuery, GetLevelClusterQuery, GetLevelGroupQuery, GetTileQuery, IBaseQueryInput, ILevelClusterQuery, ILevelGroupQuery, ITileQuery, TTtl, TileCacheOptions, TileInput, TileRenderer, TileRequest, TileServer, TileServerConfig, ZoomToDistance };
