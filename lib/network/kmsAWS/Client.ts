'use strict'; // eslint-disable-line
/* eslint new-cap: "off" */

import async from 'async';
import errors from '../../errors';
import { BucketInfo } from '../../models';
import * as werelogs from 'werelogs';
import { KMSClient, CreateAliasCommand, CreateKeyCommand, DescribeKeyCommand, ScheduleKeyDeletionCommand, EncryptCommand, DecryptCommand, GenerateDataKeyCommand, DataKeySpec } from "@aws-sdk/client-kms";
import { AwsCredentialIdentity } from "@smithy/types";
import assert from 'assert';
import { bool } from 'aws-sdk/clients/signer';

const ACCOUNT_ALIAS_PREFIX = "alias/s3user-";

/**
 * Normalize errors according to arsenal definitions
 * @param err - an Error instance or a message string
 * @returns - arsenal error
 *
 * @note Copied from the KMIP implementation
 */
function _arsenalError(err: string | Error) {
    const messagePrefix = 'AWS_KMS:';
    if (typeof err === 'string') {
        return errors.InternalError
            .customizeDescription(`${messagePrefix} ${err}`);
    } else if (
        err instanceof Error ||
        // INFO: The second part is here only for Jest, to remove when we'll be
        //   fully migrated to TS
        // @ts-expect-error
        (err && typeof err.message === 'string')
    ) {
        return errors.InternalError
            .customizeDescription(`${messagePrefix} ${err.message}`);
    }
    return errors.InternalError
        .customizeDescription(`${messagePrefix} Unspecified error`);
}

export default class Client {
    client: KMSClient;
    options: any;

    /**
     * Construct a high level KMIP driver suitable for cloudserver
     * @param options - Instance options
     * @param options.kmsAWS - AWS client options
     * @param options.kmsAWS.region - KMS region
     * @param options.kmsAWS.endpoint - Endpoint URL of the KMS service
     * @param options.kmsAWS.ak - Application Key
     * @param options.kmsAWS.sk - Secret Key
     * @param options.kmsAWS.perUserKey - per user key (true), or per bucket key (false)
     * @param logger - Logger
     * 
     * This client also looks in the standard AWS configuration files (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).
     * If no option is passed to this constructor, the client will try to get it from the configuration file.
     */
    constructor(
        options: {
            kmsAWS: {
                region?: string,
                endpoint?: string,
                ak?: string,
                sk?: string,
                perUserKey?: bool,
            }
        },
        logger: werelogs.Logger
    ) {
        let credentials: {credentials: AwsCredentialIdentity} | null = null;
        if (options.kmsAWS.ak && options.kmsAWS.sk) {
            credentials = {credentials: {
                accessKeyId: options.kmsAWS.ak,
                secretAccessKey: options.kmsAWS.sk,
            }};
        }

        this.client = new KMSClient({
            region: options.kmsAWS.region,
            endpoint: options.kmsAWS.endpoint,
            ...credentials
        });

        this.options = {
            perUserKey: options.kmsAWS.perUserKey
        };

        // Explicit the usage of per user keys.
        if (this.options.perUserKey) {
            logger.info("Using per-User Keys instead of per-bucket keys (existing keys are preserved)");
        }
    }

    /**
     * Get an account key ID
     *
     * @param userCanonicalId - The user ID
     * @returns - The Key ID for the user's account
     */
    getAccountKeyId(userCanonicalId: string) {
        return ACCOUNT_ALIAS_PREFIX + userCanonicalId;
    }

    /**
     * Create a new cryptographic key managed by the server for the specified user
     * (using an alias containing the user cannonical ID).
     *
     * @param alias - Alias of the user's key to create
     * @param logger - Werelog logger object
     * @param cb - The callback(err: Error, bucketKeyId: String)
     */
    _createUserKey (alias: string, logger: werelogs.Logger, cb: any) {
        async.waterfall([
            (next) => {
                // First create a new key for the user ...
                const cmdCreateKey = new CreateKeyCommand({});
                this.client.send(cmdCreateKey, (err, create_data) => {
                    if (err) {
                        const error = _arsenalError(err);
                        logger.error("AWS_KMS::createUserKey CreateKey failed", {err, alias});
                        next (error);
                    } else {
                        const keyId = create_data?.KeyMetadata?.KeyId;
                        if (keyId === undefined) {
                            const error = _arsenalError(err);
                            logger.error("AWS_KMS::createUserKey CreateKey didn't returned key id", {err, alias});
                            next (error);
                        } else {
                            next(null, keyId)
                        }
                    }
                });
            },
            (keyId, next) => {
                // ... then put an alias on the created-key so we can access it through the alias (ie: user id).
                const cmdCreateAlias = new CreateAliasCommand({AliasName: alias, TargetKeyId: keyId});
                this.client.send(cmdCreateAlias, (err, data) => {
                    if (err) {
                        const error = _arsenalError(err);
                        logger.error("AWS_KMS::createUserKey CreateAlias failed", {err, alias});
                        next (error);
                    } else {
                        logger.trace("AWS_KMS::createUserKey Key successfully created", {data, alias});

                        next (null, alias);
                    }
                });
            }
        ],
        (err, alias) => cb(err, alias)
        );
    }

    /**
     * Check and returns the user's account cryptographic key managed by the server.
     * The key is created only if it doesn't already exist.
     *
     * @param userCanonicalId - The user ID
     * @param logger - Werelog logger object
     * @param cb - The callback(err: Error, bucketKeyId: String)
     */
    getOrCreateAccountKey(userCanonicalId: string, logger: werelogs.Logger, cb: any) {
        logger.debug("AWS KMS: createUserKey", {userCanonicalId});

        const alias = this.getAccountKeyId(userCanonicalId);
        const cmdDescribe = new DescribeKeyCommand({KeyId: alias});
        this.client.send(cmdDescribe, (err, data) => {
            if (err === null) {
                // Happy path: the key already exists.
                logger.trace("AWS KMS: createUserKey, key already exists", {userCanonicalId, KeyMetadata: data?.KeyMetadata});
                cb(null, alias);
            } else {
                if (err.name == "NotFoundException") {
                    logger.debug("AWS_KMS::createUserKey, key doesn't exists", {err, userCanonicalId});

                    this._createUserKey(alias, logger, cb);
                } else {
                    const error = _arsenalError(err);
                    logger.error("AWS_KMS::createUserKey DescribeKey failed", {err, userCanonicalId});
                    cb (error);
                }
            }
        });
    }

    /**
     * Create a cryptographic key managed by the server,
     * for a specific bucket.
     * Depending on the value of this.options.perUserKey:
     * - false: always create a new key for the bucket,
     * - true: use the account key (create it if it doesn't exist)
     *
     * @param bucket - The bucket info object
     * @param logger - Werelog logger object
     * @param cb - The callback(err: Error, bucketKeyId: String)
     */
    createBucketKey(bucket: BucketInfo, logger: werelogs.Logger, cb: any) {
        if (this.options.perUserKey) {
            return this.getOrCreateAccountKey(bucket.getOwner(), logger, cb);
        }

        logger.debug("AWS KMS: createBucketKey", {BucketName: bucket.getName()});

        const command = new CreateKeyCommand({});
        this.client.send(command, (err, data) => {
            if (err) {
                const error = _arsenalError(err);
                logger.error("AWS_KMS::createBucketKey", {err, BucketName: bucket.getName()});
                cb (error);
            } else {
                logger.debug("AWS KMS: createBucketKey", {BucketName: bucket.getName(), KeyMetadata: data?.KeyMetadata});
                cb(null, data?.KeyMetadata?.KeyId);
            }
          });
    }

    /**
     * Destroy a cryptographic key managed by the server, for a specific bucket.
     * @param bucketKeyId - The bucket key Id
     * @param logger - Werelog logger object
     * @param cb - The callback(err: Error)
     */
    destroyBucketKey(bucketKeyId: string, logger: werelogs.Logger, cb: any) {
        logger.debug("AWS KMS: destroyBucketKey", {bucketKeyId: bucketKeyId});

        if (bucketKeyId.startsWith(ACCOUNT_ALIAS_PREFIX)) {
            // The key is an alias to the user's account global key.
            // This key is shared between all the buckets of the account and should survive the bucket deletion
            logger.info("AWS KMS: destroyBucketKey, this is an account key, keep it.", {bucketKeyId: bucketKeyId});
            process.nextTick(() => {
                cb();
            });
            return;
        }

        // Schedule a deletion in 7 days (the minimum value on this API)
        const command = new ScheduleKeyDeletionCommand({KeyId: bucketKeyId, PendingWindowInDays: 7});
        this.client.send(command, (err, data) => {
            if (err) {
                const error = _arsenalError(err);
                logger.error("AWS_KMS::destroyBucketKey", {err});
                cb (error);
            } else {
                // Sanity check
                if (data?.KeyState != "PendingDeletion") {
                    const error = _arsenalError("Key is not in PendingDeletion state")
                    logger.error("AWS_KMS::destroyBucketKey", {err, data});
                    cb(error);
                } else {
                    cb();
                }
            }
        });
    }

    /**
     * @param cryptoScheme - crypto scheme version number
     * @param masterKeyId - key to retrieve master key
     * @param logger - werelog logger object
     * @param cb - callback
     * @callback called with (err, plainTextDataKey: Buffer, cipheredDataKey: Buffer)
     */
    generateDataKey(
        cryptoScheme: number,
        masterKeyId: string,
        logger: werelogs.Logger,
        cb: any,
    ) {
        logger.debug("AWS KMS: generateDataKey", {cryptoScheme, masterKeyId});

        // Only support cryptoScheme v1
        assert.strictEqual (cryptoScheme, 1);

        const command = new GenerateDataKeyCommand({KeyId: masterKeyId, KeySpec: DataKeySpec.AES_256});
        this.client.send(command, (err, data) => {
            if (err) {
                const error = _arsenalError(err);
                logger.error("AWS_KMS::generateDataKey", {err});
                cb (error);
            } else if (!data) {
                const error = _arsenalError("generateDataKey: empty response");
                logger.error("AWS_KMS::generateDataKey empty reponse");
                cb (error);
            } else {
                // Convert to a buffer. This allows the wrapper to use .toString("base64")
                cb(null, Buffer.from(data.Plaintext!), Buffer.from(data.CiphertextBlob!));
            }
        });
    }

    /**
     *
     * @param cryptoScheme - crypto scheme version number
     * @param masterKeyId - key to retrieve master key
     * @param plainTextDataKey - data key
     * @param logger - werelog logger object
     * @param cb - callback
     * @callback called with (err, cipheredDataKey: Buffer)
     */
    cipherDataKey(
        cryptoScheme: number,
        masterKeyId: string,
        plainTextDataKey: Buffer,
        logger: werelogs.Logger,
        cb: any,
    ) {
        logger.debug("AWS KMS: cipherDataKey", {cryptoScheme, masterKeyId});

        // Only support cryptoScheme v1
        assert.strictEqual (cryptoScheme, 1);

        const command = new EncryptCommand({KeyId: masterKeyId, Plaintext: plainTextDataKey});
        this.client.send(command, (err, data) => {
            if (err) {
                const error = _arsenalError(err);
                logger.error("AWS_KMS::cipherDataKey", {err});
                cb (error);
            } else if (!data) {
                const error = _arsenalError("cipherDataKey: empty response");
                logger.error("AWS_KMS::cipherDataKey empty reponse");
                cb (error);
            } else {
                // Convert to a buffer. This allows the wrapper to use .toString("base64")
                cb(null, Buffer.from(data.CiphertextBlob!));
            }
        });
    }

    /**
     *
     * @param cryptoScheme - crypto scheme version number
     * @param masterKeyId - key to retrieve master key
     * @param cipheredDataKey - data key
     * @param logger - werelog logger object
     * @param cb - callback
     * @callback called with (err, plainTextDataKey: Buffer)
     */
    decipherDataKey(
        cryptoScheme: number,
        masterKeyId: string,
        cipheredDataKey: Buffer,
        logger: werelogs.Logger,
        cb: any,
    ) {
        logger.debug("AWS KMS: decipherDataKey", {cryptoScheme, masterKeyId});

        // Only support cryptoScheme v1
        assert.strictEqual (cryptoScheme, 1);

        const command = new DecryptCommand({CiphertextBlob: cipheredDataKey});
        this.client.send(command, (err, data) => {
            if (err) {
                const error = _arsenalError(err);
                logger.error("AWS_KMS::decipherDataKey", {err});
                cb (error);
            } else if (!data) {
                const error = _arsenalError("decipherDataKey: empty response");
                logger.error("AWS_KMS::decipherDataKey empty reponse");
                cb (error);
            } else {
                cb(null, Buffer.from(data?.Plaintext!));
            }
        });
    }
}
