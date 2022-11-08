const assert = require('assert');
const ObjectMD = require('../../../lib/models/ObjectMD').default;
const constants = require('../../../lib/constants');
const ExternalNullVersionId = require('../../../lib/versioning/constants')
    .VersioningConstants.ExternalNullVersionId;

const retainDate = new Date();
retainDate.setDate(retainDate.getDate() + 1);
const laterDate = new Date();
laterDate.setDate(laterDate.getDate() + 5);

describe('ObjectMD class setters/getters', () => {
    let md = null;

    beforeEach(() => {
        md = new ObjectMD();
    });

    [
        // In order: data property, value to set/get, default value
        ['OwnerDisplayName', null, ''],
        ['OwnerDisplayName', 'owner-display-name'],
        ['OwnerId', null, ''],
        ['OwnerId', 'owner-id'],
        ['CacheControl', null, ''],
        ['CacheControl', 'cache-control'],
        ['ContentDisposition', null, ''],
        ['ContentDisposition', 'content-disposition'],
        ['ContentEncoding', null, ''],
        ['ContentEncoding', 'content-encoding'],
        ['Expires', null, ''],
        ['Expires', 'expire-date'],
        ['ContentLength', null, 0],
        ['ContentLength', 15000],
        ['ContentType', null, ''],
        ['ContentType', 'content-type'],
        ['LastModified', new Date().toJSON()],
        ['ContentMd5', null, ''],
        ['ContentMd5', 'content-md5'],
        ['AmzVersionId', null, 'null'],
        ['AmzVersionId', 'version-id'],
        ['AmzServerVersionId', null, ''],
        ['AmzServerVersionId', 'server-version-id'],
        ['AmzStorageClass', null, 'STANDARD'],
        ['AmzStorageClass', 'storage-class'],
        ['AmzServerSideEncryption', null, ''],
        ['AmzServerSideEncryption', 'server-side-encryption'],
        ['AmzEncryptionKeyId', null, ''],
        ['AmzEncryptionKeyId', 'encryption-key-id'],
        ['AmzEncryptionCustomerAlgorithm', null, ''],
        ['AmzEncryptionCustomerAlgorithm', 'customer-algorithm'],
        ['Acl', null, {
            Canned: 'private',
            FULL_CONTROL: [],
            WRITE_ACP: [],
            READ: [],
            READ_ACP: [],
        }],
        ['Acl', {
            Canned: 'public',
            FULL_CONTROL: ['id'],
            WRITE_ACP: ['id'],
            READ: ['id'],
            READ_ACP: ['id'],
        }],
        ['Key', null, ''],
        ['Key', 'key'],
        ['Location', null, []],
        ['Location', ['location1']],
        ['IsNull', null, false],
        ['IsNull', true],
        ['IsNull2', null, false],
        ['IsNull2', true],
        ['NullVersionId', null, undefined],
        ['NullVersionId', '111111'],
        ['NullUploadId', null, undefined],
        ['NullUploadId', 'abcdefghi'],
        ['IsDeleteMarker', null, false],
        ['IsDeleteMarker', true],
        ['VersionId', null, undefined],
        ['VersionId', '111111'],
        ['Tags', null, {}],
        ['Tags', {
            key: 'value',
        }],
        ['Tags', null, {}],
        ['UploadId', null, undefined],
        ['UploadId', 'abcdefghi'],
        ['ReplicationInfo', null, {
            status: '',
            backends: [],
            content: [],
            destination: '',
            storageClass: '',
            role: '',
            storageType: '',
            dataStoreVersionId: '',
        }],
        ['ReplicationInfo', {
            status: 'PENDING',
            backends: [{
                site: 'zenko',
                status: 'PENDING',
                dataStoreVersionId: 'a',
            }],
            content: ['DATA', 'METADATA'],
            destination: 'destination-bucket',
            storageClass: 'STANDARD',
            role: 'arn:aws:iam::account-id:role/src-resource,' +
                'arn:aws:iam::account-id:role/dest-resource',
            storageType: 'aws_s3',
            dataStoreVersionId: '',
        }],
        ['DataStoreName', null, ''],
        ['LegalHold', null, false],
        ['LegalHold', true],
        ['RetentionMode', 'GOVERNANCE'],
        ['RetentionDate', retainDate.toISOString()],
        ['OriginOp', null, ''],
    ].forEach(test => {
        const property = test[0];
        const testValue = test[1];
        const defaultValue = test[2];
        const testName = testValue === null ? 'get default' : 'get/set';
        it(`${testName}: ${property}`, () => {
            if (testValue !== null) {
                md[`set${property}`](testValue);
            }
            const value = md[`get${property}`]();
            if ((testValue !== null && typeof testValue === 'object') ||
                typeof defaultValue === 'object') {
                assert.deepStrictEqual(value, testValue || defaultValue);
            } else if (testValue !== null) {
                assert.strictEqual(value, testValue);
            } else {
                assert.strictEqual(value, defaultValue);
            }
        });
    });

    it('ObjectMD::setReplicationSiteStatus', () => {
        md.setReplicationInfo({
            backends: [{
                site: 'zenko',
                status: 'PENDING',
                dataStoreVersionId: 'a',
            }],
        });
        md.setReplicationSiteStatus('zenko', 'COMPLETED');
        assert.deepStrictEqual(md.getReplicationInfo().backends, [{
            site: 'zenko',
            status: 'COMPLETED',
            dataStoreVersionId: 'a',
        }]);
    });

    it('ObjectMD::setReplicationBackends', () => {
        md.setReplicationBackends([{
            site: 'a',
            status: 'b',
            dataStoreVersionId: 'c',
        }]);
        assert.deepStrictEqual(md.getReplicationBackends(), [{
            site: 'a',
            status: 'b',
            dataStoreVersionId: 'c',
        }]);
    });

    it('ObjectMD::setReplicationStorageClass', () => {
        md.setReplicationStorageClass('a');
        assert.strictEqual(md.getReplicationStorageClass(), 'a');
    });

    it('ObjectMD::getReplicationSiteStatus', () => {
        md.setReplicationInfo({
            backends: [{
                site: 'zenko',
                status: 'PENDING',
                dataStoreVersionId: 'a',
            }],
        });
        assert.strictEqual(md.getReplicationSiteStatus('zenko'), 'PENDING');
    });

    it('ObjectMD::setReplicationSiteDataStoreVersionId', () => {
        md.setReplicationInfo({
            backends: [{
                site: 'zenko',
                status: 'PENDING',
                dataStoreVersionId: 'a',
            }],
        });
        md.setReplicationSiteDataStoreVersionId('zenko', 'b');
        assert.deepStrictEqual(md.getReplicationInfo().backends, [{
            site: 'zenko',
            status: 'PENDING',
            dataStoreVersionId: 'b',
        }]);
    });

    it('ObjectMD::getReplicationSiteDataStoreVersionId', () => {
        md.setReplicationInfo({
            backends: [{
                site: 'zenko',
                status: 'PENDING',
                dataStoreVersionId: 'a',
            }],
        });
        assert.strictEqual(
            md.getReplicationSiteDataStoreVersionId('zenko'), 'a');
    });

    it('ObjectMD::set/getRetentionMode', () => {
        md.setRetentionMode('COMPLIANCE');
        assert.deepStrictEqual(md.getRetentionMode(), 'COMPLIANCE');
    });

    it('ObjectMD::set/getRetentionDate', () => {
        md.setRetentionDate(laterDate.toISOString());
        assert.deepStrictEqual(md.getRetentionDate(), laterDate.toISOString());
    });

    it('ObjectMD::set/getOriginOp', () => {
        md.setOriginOp('Copy');
        assert.deepStrictEqual(md.getOriginOp(), 'Copy');
    });
});

describe('ObjectMD import from stored blob', () => {
    it('should export and import correctly the latest model version', () => {
        const md = new ObjectMD();
        const jsonMd = md.getSerialized();
        const importedRes = ObjectMD.createFromBlob(jsonMd);
        assert.ifError(importedRes.error);
        const importedMd = importedRes.result;
        assert.deepStrictEqual(md, importedMd);
    });

    it('should convert old location to new location', () => {
        const md = new ObjectMD();
        const value = md.getValue();
        value['md-model-version'] = 1;
        value.location = 'stringLocation';
        const jsonMd = JSON.stringify(value);
        const importedRes = ObjectMD.createFromBlob(jsonMd);
        assert.strictEqual(importedRes.error, undefined);
        const importedMd = importedRes.result;
        const valueImported = importedMd.getValue();
        assert.strictEqual(valueImported['md-model-version'],
            constants.mdModelVersion);
        assert.deepStrictEqual(valueImported.location,
            [{ key: 'stringLocation' }]);
    });

    it('should keep null location as is', () => {
        const md = new ObjectMD();
        const value = md.getValue();
        value.location = null;
        const jsonMd = JSON.stringify(value);
        const importedRes = ObjectMD.createFromBlob(jsonMd);
        assert.strictEqual(importedRes.error, undefined);
        const importedMd = importedRes.result;
        const valueImported = importedMd.getValue();
        assert.deepStrictEqual(valueImported.location, null);
        importedMd.setLocation([]);
        assert.deepStrictEqual(importedMd.getValue().location, null);
    });

    it('should add dataStoreName attribute if missing', () => {
        const md = new ObjectMD();
        const value = md.getValue();
        value['md-model-version'] = 2;
        delete value.dataStoreName;
        const jsonMd = JSON.stringify(value);
        const importedRes = ObjectMD.createFromBlob(jsonMd);
        assert.strictEqual(importedRes.error, undefined);
        const importedMd = importedRes.result;
        const valueImported = importedMd.getValue();
        assert.strictEqual(valueImported['md-model-version'],
            constants.mdModelVersion);
        assert.notStrictEqual(valueImported.dataStoreName, undefined);
    });

    it('should return undefined for dataStoreVersionId if no object location',
        () => {
            const md = new ObjectMD();
            const value = md.getValue();
            const jsonMd = JSON.stringify(value);
            const importedRes = ObjectMD.createFromBlob(jsonMd);
            assert.strictEqual(importedRes.error, undefined);
            const importedMd = importedRes.result;
            assert.strictEqual(importedMd.getDataStoreVersionId(), undefined);
        });

    it('should get dataStoreVersionId if saved in object location', () => {
        const md = new ObjectMD();
        const dummyLocation = {
            dataStoreVersionId: 'data-store-version-id',
        };
        md.setLocation([dummyLocation]);
        const value = md.getValue();
        const jsonMd = JSON.stringify(value);
        const importedRes = ObjectMD.createFromBlob(jsonMd);
        assert.strictEqual(importedRes.error, undefined);
        const importedMd = importedRes.result;
        assert.strictEqual(importedMd.getDataStoreVersionId(),
            dummyLocation.dataStoreVersionId);
    });

    it('should return an error if blob is malformed JSON', () => {
        const importedRes = ObjectMD.createFromBlob('{BAD JSON}');
        assert.notStrictEqual(importedRes.error, undefined);
        assert.strictEqual(importedRes.result, undefined);
    });
});

describe('getAttributes static method', () => {
    it('should return object metadata attributes', () => {
        const attributes = ObjectMD.getAttributes();
        const expectedResult = {
            'owner-display-name': true,
            'owner-id': true,
            'cache-control': true,
            'content-disposition': true,
            'content-encoding': true,
            'expires': true,
            'content-length': true,
            'content-type': true,
            'content-md5': true,
            'x-amz-version-id': true,
            'x-amz-server-version-id': true,
            'x-amz-storage-class': true,
            'x-amz-server-side-encryption': true,
            'x-amz-server-side-encryption-aws-kms-key-id': true,
            'x-amz-server-side-encryption-customer-algorithm': true,
            'x-amz-website-redirect-location': true,
            'acl': true,
            'key': true,
            'location': true,
            'isNull': true,
            'isNull2': true,
            'nullVersionId': true,
            'nullUploadId': true,
            'isDeleteMarker': true,
            'versionId': true,
            'tags': true,
            'uploadId': true,
            'replicationInfo': true,
            'dataStoreName': true,
            'last-modified': true,
            'md-model-version': true,
            'originOp': true,
        };
        assert.deepStrictEqual(attributes, expectedResult);
    });
});

describe('ObjectMD::getReducedLocations', () => {
    it('should not alter an array when each part has only one element', () => {
        const md = new ObjectMD();
        const locations = [
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 1,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '4e67844b674b093a9e109d42172922ea1f32ec12',
                size: 3,
                start: 1,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
        ];
        md.setLocation(locations);
        assert.deepStrictEqual(md.getReducedLocations(), locations);
    });

    it('should reduce an array when first part is > 1 element', () => {
        const md = new ObjectMD();
        md.setLocation([
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 1,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: 'deebfb287cfcee1d137b0136562d2d776ba491e1',
                size: 1,
                start: 1,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '4e67844b674b093a9e109d42172922ea1f32ec12',
                size: 3,
                start: 2,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
        ]);
        assert.deepStrictEqual(md.getReducedLocations(), [
            {
                key: 'deebfb287cfcee1d137b0136562d2d776ba491e1',
                size: 2,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '4e67844b674b093a9e109d42172922ea1f32ec12',
                size: 3,
                start: 2,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
        ]);
    });

    it('should reduce an array when second part is > 1 element', () => {
        const md = new ObjectMD();
        md.setLocation([
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 1,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: 'deebfb287cfcee1d137b0136562d2d776ba491e1',
                size: 1,
                start: 1,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
            {
                key: '4e67844b674b093a9e109d42172922ea1f32ec12',
                size: 3,
                start: 2,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
        ]);
        assert.deepStrictEqual(md.getReducedLocations(), [
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 1,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '4e67844b674b093a9e109d42172922ea1f32ec12',
                size: 4,
                start: 1,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
        ]);
    });

    it('should reduce an array when multiple parts are > 1 element', () => {
        const md = new ObjectMD();
        md.setLocation([
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 1,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: 'c1c1e055b19eb5a61adb8a665e626ff589cff234',
                size: 2,
                start: 1,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: 'deebfb287cfcee1d137b0136562d2d776ba491e1',
                size: 1,
                start: 3,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '8e67844b674b093a9e109d42172922ea1f32ec14',
                size: 3,
                start: 4,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
            {
                key: 'd1d1e055b19eb5a61adb8a665e626ff589cff233',
                size: 10,
                start: 7,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
            {
                key: '0e67844b674b093a9e109d42172922ea1f32ec11',
                size: 10,
                start: 17,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
            {
                key: '8e67844b674b093a9e109d42172922ea1f32ec14',
                size: 15,
                start: 27,
                dataStoreName: 'file',
                dataStoreETag: '3:1ca655158ca025aa00a818b6b81f9e4c',
            },
            {
                key: '7e67844b674b093a9e109d42172922ea1f32ec1f',
                size: 2,
                start: 42,
                dataStoreName: 'file',
                dataStoreETag: '3:1ca655158ca025aa00a818b6b81f9e4c',
            },
            {
                key: '1237844b674b093a9e109d42172922ea1f32ec19',
                size: 6,
                start: 44,
                dataStoreName: 'file',
                dataStoreETag: '4:afa655158ca025aa00a818b6b81f9e4d',
            },
            {
                key: '4567844b674b093a9e109d42172922ea1f32ec00',
                size: 4,
                start: 50,
                dataStoreName: 'file',
                dataStoreETag: '4:afa655158ca025aa00a818b6b81f9e4d',
            },
            {
                key: '53d7844b674b093a9e109d42172922ea1f32ec02',
                size: 9,
                start: 54,
                dataStoreName: 'file',
                dataStoreETag: '4:afa655158ca025aa00a818b6b81f9e4d',
            },
            {
                key: '6f6d7844b674b093a9e109d42172922ea1f32ec01',
                size: 2,
                start: 63,
                dataStoreName: 'file',
                dataStoreETag: '4:afa655158ca025aa00a818b6b81f9e4d',
            },
        ]);
        assert.deepStrictEqual(md.getReducedLocations(), [
            {
                key: 'deebfb287cfcee1d137b0136562d2d776ba491e1',
                size: 4,
                start: 0,
                dataStoreName: 'file',
                dataStoreETag: '1:0e5a6f42662652d44fcf978399ef5709',
            },
            {
                key: '0e67844b674b093a9e109d42172922ea1f32ec11',
                size: 23,
                start: 4,
                dataStoreName: 'file',
                dataStoreETag: '2:9ca655158ca025aa00a818b6b81f9e48',
            },
            {
                key: '7e67844b674b093a9e109d42172922ea1f32ec1f',
                size: 17,
                start: 27,
                dataStoreName: 'file',
                dataStoreETag: '3:1ca655158ca025aa00a818b6b81f9e4c',
            },
            {
                key: '6f6d7844b674b093a9e109d42172922ea1f32ec01',
                size: 21,
                start: 44,
                dataStoreName: 'file',
                dataStoreETag: '4:afa655158ca025aa00a818b6b81f9e4d',
            },
        ]);
    });
});

describe('ObjectMD::getVersionId', () => {
    let objMd = null;
    const versionId = '98451712418844999999RG001  22019.0';
    beforeEach(() => {
        objMd = new ObjectMD();
    });
    it('should return undefined when object is non versioned', () => {
        assert.strictEqual(objMd.getVersionId(), undefined);
    });
    it('should return versionId when object versioned', () => {
        objMd.setVersionId(versionId);
        assert.strictEqual(objMd.getVersionId(), versionId);
    });
    it('should return "null" when object is in versioning suspended mode', () => {
        objMd.setVersionId(versionId);
        objMd.setIsNull(true);
        assert.strictEqual(objMd.getVersionId(), ExternalNullVersionId);
    });
});

describe('ObjectMD::getEncodedVersionId', () => {
    let objMd = null;
    const versionId = '98451712418844999999RG001  22019.0';
    const encodedVersionId = '39383435313731323431383834343939393939395247303031202032323031392e30';
    beforeEach(() => {
        objMd = new ObjectMD();
    });
    it('should return undefined when object is non versioned', () => {
        assert.strictEqual(objMd.getEncodedVersionId(), undefined);
    });
    it('should return versionId when object versioned', () => {
        objMd.setVersionId(versionId);
        assert.strictEqual(objMd.getEncodedVersionId(), encodedVersionId);
    });
    it('should return "null" when object is in versioning suspended mode', () => {
        objMd.setVersionId(versionId);
        objMd.setIsNull(true);
        assert.strictEqual(objMd.getEncodedVersionId(), ExternalNullVersionId);
    });
});
