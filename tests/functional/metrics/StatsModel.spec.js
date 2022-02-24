'use strict'; // eslint-disable-line strict

const assert = require('assert');
const async = require('async');

const RedisClient = require('../../../lib/metrics/RedisClient').default;
const StatsModel = require('../../../lib/metrics/StatsModel').default;

// setup redis client
const config = {
    host: '127.0.0.1',
    port: 6379,
    enableOfflineQueue: true,
};
const fakeLogger = {
    trace: () => {},
    error: () => {},
};
const redisClient = new RedisClient(config, fakeLogger);

// setup stats model
const STATS_INTERVAL = 300; // 5 minutes
const STATS_EXPIRY = 86400; // 24 hours
const statsModel = new StatsModel(redisClient, STATS_INTERVAL, STATS_EXPIRY);

function setExpectedStats(expected) {
    return expected.concat(
        Array((STATS_EXPIRY / STATS_INTERVAL) - expected.length).fill(0));
}

// Since many methods were overwritten, these tests should validate the changes
// made to the original methods
describe('StatsModel class', () => {
    const id = 'arsenal-test';
    const id2 = 'test-2';
    const id3 = 'test-3';

    afterEach(() => redisClient.clear(() => {}));

    it('should convert a 2d array columns into rows and vice versa using _zip',
        () => {
            const arrays = [
                [1, 2, 3],
                [4, 5, 6],
                [7, 8, 9],
            ];

            const res = statsModel._zip(arrays);
            const expected = [
                [1, 4, 7],
                [2, 5, 8],
                [3, 6, 9],
            ];

            assert.deepStrictEqual(res, expected);
        });

    it('_zip should return an empty array if given an invalid array', () => {
        const arrays = [];

        const res = statsModel._zip(arrays);

        assert.deepStrictEqual(res, []);
    });

    it('_getCount should return a an array of all valid integer values',
        () => {
            const res = statsModel._getCount([
                [null, '1'],
                [null, '2'],
                [null, null],
            ]);
            assert.deepStrictEqual(res, setExpectedStats([1, 2, 0]));
        });

    it('should correctly record a new request by default one increment',
        done => {
            async.series([
                next => {
                    statsModel.reportNewRequest(id, (err, res) => {
                        assert.ifError(err);

                        const expected = [[null, 1], [null, 1]];
                        assert.deepStrictEqual(res, expected);
                        next();
                    });
                },
                next => {
                    statsModel.reportNewRequest(id, (err, res) => {
                        assert.ifError(err);

                        const expected = [[null, 2], [null, 1]];
                        assert.deepStrictEqual(res, expected);
                        next();
                    });
                },
            ], done);
        });

    it('should record new requests by defined amount increments', done => {
        function noop() {}

        async.series([
            next => {
                statsModel.reportNewRequest(id, 9);
                statsModel.getStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);

                    assert.deepStrictEqual(res.requests, setExpectedStats([9]));
                    next();
                });
            },
            next => {
                statsModel.reportNewRequest(id);
                statsModel.getStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);

                    assert.deepStrictEqual(res.requests,
                        setExpectedStats([10]));
                    next();
                });
            },
            next => {
                statsModel.reportNewRequest(id, noop);
                statsModel.getStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);

                    assert.deepStrictEqual(res.requests,
                        setExpectedStats([11]));
                    next();
                });
            },
        ], done);
    });

    it('should correctly record a 500 on the server', done => {
        statsModel.report500(id, (err, res) => {
            assert.ifError(err);

            const expected = [[null, 1], [null, 1]];
            assert.deepStrictEqual(res, expected);
            done();
        });
    });

    it('should respond back with total requests as an array', done => {
        async.series([
            next => {
                statsModel.reportNewRequest(id, err => {
                    assert.ifError(err);
                    next();
                });
            },
            next => {
                statsModel.report500(id, err => {
                    assert.ifError(err);
                    next();
                });
            },
            next => {
                statsModel.getStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);

                    const expected = {
                        'requests': setExpectedStats([1]),
                        '500s': setExpectedStats([1]),
                        'sampleDuration': STATS_EXPIRY,
                    };
                    assert.deepStrictEqual(res, expected);
                    next();
                });
            },
        ], done);
    });

    it('should not crash on empty results', done => {
        async.series([
            next => {
                statsModel.getStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);
                    const expected = {
                        'requests': setExpectedStats([]),
                        '500s': setExpectedStats([]),
                        'sampleDuration': STATS_EXPIRY,
                    };
                    assert.deepStrictEqual(res, expected);
                    next();
                });
            },
            next => {
                statsModel.getAllStats(fakeLogger, id, (err, res) => {
                    assert.ifError(err);
                    const expected = {
                        'requests': setExpectedStats([]),
                        '500s': setExpectedStats([]),
                        'sampleDuration': STATS_EXPIRY,
                    };
                    assert.deepStrictEqual(res, expected);
                    next();
                });
            },
        ], done);
    });

    it('should return a zero-filled array if no ids are passed to getAllStats',
        done => {
            statsModel.getAllStats(fakeLogger, [], (err, res) => {
                assert.ifError(err);

                assert.deepStrictEqual(res.requests, setExpectedStats([]));
                assert.deepStrictEqual(res['500s'], setExpectedStats([]));
                done();
            });
        });

    it('should get accurately reported data for given id from getAllStats',
        done => {
            statsModel.reportNewRequest(id, 9);
            statsModel.reportNewRequest(id2, 2);
            statsModel.reportNewRequest(id3, 3);
            statsModel.report500(id);

            async.series([
                next => {
                    statsModel.getAllStats(fakeLogger, [id], (err, res) => {
                        assert.ifError(err);

                        assert.equal(res.requests[0], 9);
                        assert.equal(res['500s'][0], 1);
                        next();
                    });
                },
                next => {
                    statsModel.getAllStats(fakeLogger, [id, id2, id3],
                        (err, res) => {
                            assert.ifError(err);

                            assert.equal(res.requests[0], 14);
                            assert.deepStrictEqual(res.requests,
                                setExpectedStats([14]));
                            next();
                        });
                },
            ], done);
        });

    it('should normalize to the nearest hour using normalizeTimestampByHour',
        () => {
            const date = new Date('2018-09-13T23:30:59.195Z');
            const newDate = new Date(statsModel.normalizeTimestampByHour(date));

            assert.strictEqual(date.getHours(), newDate.getHours());
            assert.strictEqual(newDate.getMinutes(), 0);
            assert.strictEqual(newDate.getSeconds(), 0);
            assert.strictEqual(newDate.getMilliseconds(), 0);
        });

    it('should get previous hour using _getDatePreviousHour', () => {
        const date = new Date('2018-09-13T23:30:59.195Z');
        const newDate = statsModel._getDatePreviousHour(new Date(date));

        const millisecondsInOneHour = 3600000;
        assert.strictEqual(date - newDate, millisecondsInOneHour);
    });

    it('should get an array of hourly timestamps using getSortedSetHours',
        () => {
            const epoch = 1536882476501;
            const millisecondsInOneHour = 3600000;

            const expected = [];
            let dateInMilliseconds = statsModel.normalizeTimestampByHour(
                new Date(epoch));

            for (let i = 0; i < 24; i++) {
                expected.push(dateInMilliseconds);
                dateInMilliseconds -= millisecondsInOneHour;
            }
            const res = statsModel.getSortedSetHours(epoch);

            assert.deepStrictEqual(res, expected);
        });

    it('should apply TTL on a new sorted set using addToSortedSet', done => {
        const key = 'a-test-key';
        const score = 100;
        const value = 'a-value';

        const now = Date.now();
        const nearestHour = statsModel.normalizeTimestampByHour(new Date(now));

        statsModel.addToSortedSet(key, score, value, (err, res) => {
            assert.ifError(err);
            // check both a "zadd" and "expire" occurred
            assert.equal(res, 1);
            redisClient.ttl(key, (err, res) => {
                assert.ifError(err);
                // assert this new set has a ttl applied
                assert(res > 0);

                const adjustmentSecs = now - nearestHour;
                const msInADay = 24 * 60 * 60 * 1000;
                const msInAnHour = 60 * 60 * 1000;
                const upperLimitSecs =
                    Math.ceil((msInADay - adjustmentSecs) / 1000);
                const lowerLimitSecs =
                    Math.floor((msInADay - adjustmentSecs - msInAnHour) / 1000);

                // assert new ttl is between 23 and 24 hours adjusted by time
                // elapsed since normalized hourly time
                assert(res >= lowerLimitSecs);
                assert(res <= upperLimitSecs);

                done();
            });
        });
    });
});
