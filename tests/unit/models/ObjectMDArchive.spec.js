const assert = require('assert');
const ObjectMDArchive = require('../../../lib/models/ObjectMDArchive');

const testArchive = {
    archiveInfo: {
        any: 'value',
    },
    restoreRequestedAt: new Date(0),
    restoreRequestedDays: 5,
    restoreCompletedAt: new Date(1000),
    restoreWillExpireAt: new Date(10000),
};

const archive = new ObjectMDArchive(
    testArchive.archiveInfo,
    testArchive.restoreRequestedAt,
    testArchive.restoreRequestedDays,
    testArchive.restoreCompletedAt,
    testArchive.restoreWillExpireAt,
);

describe('ObjectMDArchive value', () => {
    it('should return the correct value', () => {
        const amzRestoreObj = archive.getValue();
        assert.deepStrictEqual(amzRestoreObj, archive._data);
    });
});

describe('ObjectMDArchive setters/getters', () => {
    it('should control the archiveInfo attribute', () => {
        const info = {
            test: 'data',
        };
        archive.setArchiveInfo(info);
        assert.deepStrictEqual(archive.getArchiveInfo(),
            info);
    });
    it('should control the restoreRequestedAt attribute', () => {
        const requestedAt = new Date(123456);
        archive.setRestoreRequestedAt(requestedAt);
        assert.deepStrictEqual(archive.getRestoreRequestedAt(),
            requestedAt);
    });
    it('should control the restoreRequestedDays attribute', () => {
        const requestedDays = 8;
        archive.setRestoreRequestedDays(requestedDays);
        assert.deepStrictEqual(archive.getRestoreRequestedDays(),
            requestedDays);
    });
    it('should control the restoreCompletedAt attribute', () => {
        const completedAt = new Date(123456);
        archive.setRestoreCompletedAt(completedAt);
        assert.deepStrictEqual(archive.getRestoreCompletedAt(),
            completedAt);
    });
    it('should control the restoreWillExpireAt attribute', () => {
        const willExpireAt = new Date(123456);
        archive.setRestoreWillExpireAt(willExpireAt);
        assert.deepStrictEqual(archive.getRestoreWillExpireAt(),
            willExpireAt);
    });
});
