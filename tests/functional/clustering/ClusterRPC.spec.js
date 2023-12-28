'use strict'; // eslint-disable-line

const http = require('http');
const readline = require('readline');
const spawn = require('child_process').spawn;

const TEST_SERVER_PORT = 8800;
const NB_WORKERS = 4;

let testServer = null;

/*
 * jest tests don't correctly support cluster mode with child forked
 * processes, instead we use an external test server that launches
 * each test based on the provided URL, and returns either 200 for
 * success or 500 for failure. A crash would also cause a failure
 * from the client side.
 */
function startTestServer(done) {
    testServer = spawn('node', [
        `${__dirname}/ClusterRPC-test-server.js`,
        TEST_SERVER_PORT,
        NB_WORKERS,
    ]);
    // gather server stderr to display test failures info
    testServer.stdout.pipe(process.stdout);
    testServer.stderr.pipe(process.stderr);

    const rl = readline.createInterface({
        input: testServer.stdout,
    });
    let nbListeningWorkers = 0;
    rl.on('line', line => {
        if (line === 'Worker is listening') {
            nbListeningWorkers++;
            if (nbListeningWorkers === NB_WORKERS) {
                rl.close();
                done();
            }
        }
    });
}

function stopTestServer(done) {
    testServer.kill('SIGTERM');
    testServer.on('close', done);
}

function runTest(testUrl, cb) {
    const req = http.request(`http://localhost:${TEST_SERVER_PORT}/${testUrl}`, res => {
        res
            .on('data', () => {})
            .on('end', () => {
                expect(res.statusCode).toEqual(200);
                cb();
            })
            .on('error', err => cb(err));
    });
    req
        .end()
        .on('error', err => cb(err));
}

describe('ClusterRPC', () => {
    beforeAll(done => startTestServer(done));
    afterAll(done => stopTestServer(done));

    it('should send a successful command to all workers', done => {
        runTest('successful-command', done);
    });

    it('should error if "toWorkers" field is not "*"', done => {
        runTest('unsupported-to-workers', done);
    });

    it('should error if handler name is not known', done => {
        runTest('unsupported-handler', done);
    });

    it('should error if "uids" field is not passed', done => {
        runTest('missing-uids', done);
    });

    it('should error if two simultaneous commands with same "uids" field are sent', done => {
        runTest('duplicate-uids', done);
    });

    it('should timeout if one or more workers don\'t respond in allocated time', done => {
        runTest('worker-timeout', done);
    });

    it('should return worker errors in results array', done => {
        runTest('unsuccessful-worker', done);
    });

    it('should send a successful command to all workers after an extra worker is spawned', done => {
        const rl = readline.createInterface({
            input: testServer.stdout,
        });
        rl.on('line', line => {
            if (line === 'Worker is listening') {
                rl.close();
                runTest('successful-command-with-extra-worker', done);
            }
        });
        // The test server spawns a new worker when it receives SIGUSR1
        testServer.kill('SIGUSR1');
    });
});
