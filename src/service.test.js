import fs from 'fs';
import path from 'path';
import assert from 'node:assert';
import {describe, it, before, after, beforeEach} from 'node:test';
import HttpStatus from 'http-status';
import * as testContext from './service.js';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';
import {Agent, MockAgent, setGlobalDispatcher} from 'undici';
import createDebugLogger from 'debug';

const debug = createDebugLogger('@natlibfi/passport-melinda-aleph:test');

const FIXTURES_PATH = path.join(import.meta.dirname, '../test-fixtures/authentication');
const authnResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse1.xml'), 'utf8');
const authnResponse2 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse2.xml'), 'utf8');
const authnResponse3 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse3.xml'), 'utf8');
const authnResponse4 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse4.xml'), 'utf8');
const authzResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authzResponse1.json'), 'utf8');
const userData1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'userData1.json'), 'utf8');
const userData2 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'userData2.json'), 'utf8');

const mockAgent = new MockAgent();

// We have same URL for both services, so that undici mock can interrupt both calls
const xServiceURL = 'https://authn';
const ownAuthzURL = 'https://authn';
const ownAuthApiKey = 'foobar'; // njsscan-ignore: node_api_key
const userLibrary = 'foo'; // njsscan-ignore: node_username
const username = 'foo'; // njsscan-ignore: node_username
const password = 'bar'; // njsscan-ignore: node_password

// eslint-disable-next-line max-lines-per-function
describe('authentication/service', () => {
  // eslint-disable-next-line max-lines-per-function
  describe('factory', () => {
    it('Should create the expected object', () => {
      const service = testContext.createService({xServiceURL: 'https://authn', userLibrary: 'foo'});
      assert.ok(service.constructor === Object );
      assert.ok(typeof service.authenticate === 'function');
      //assert.ok(service.authenticate());
      //expect(service).to.be.an('object').and.respondTo('authenticate');
    });

    // eslint-disable-next-line max-lines-per-function
    describe('#authenticate', () => {

      before(() => {
        setGlobalDispatcher(mockAgent);
        mockAgent.disableNetConnect();
      });

      beforeEach(() => {
        debug(`============`);
      });

      after(async () => {
        await mockAgent.close();
        setGlobalDispatcher(new Agent());
      });

      it('Should authenticate the user succesfully', async () => {
        debug(`TEST 1`);

        const mockPool = mockAgent.get('https://authn');

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar
        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse1);

        // https://authn/foo
        mockPool.intercept({path: `/${username}`})
          .reply(HttpStatus.OK, authzResponse1);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});
        const user = await service.authenticate({username, password});

        assert.deepEqual(user, JSON.parse(userData1));
      });

      it('Should authenticate the user with two middle names succesfully', async () => {
        debug(`TEST 2`);

        const mockPool = mockAgent.get('https://authn');

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar
        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse4);

        // https://authn/foo
        mockPool.intercept({path: `/${username}`})
          .reply(HttpStatus.OK, authzResponse1);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});
        const user = await service.authenticate({username, password});

        assert.deepEqual(user, JSON.parse(userData2));
      });


      it('Should fail to authenticate the user (Invalid credentials)', async () => {

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse2);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          debug(`Error: ${err.message}`);
          debug(`Error: ${JSON.stringify(err.status)} ${JSON.stringify(err.payload)}`);
          assert.ok(err instanceof AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Reply not ok)', async () => {

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse3);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          debug(`Error: ${err.message}`);
          debug(`Error: ${JSON.stringify(err.status)} ${JSON.stringify(err.payload)}`);
          assert.ok(err instanceof AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Unexpected error)', async () => {

        // We have same URL for both services, so that undici mock can interrupt both calls
        const mockPool = mockAgent.get('https://authn');

        // 500 error from X-server
        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(500);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          debug(`Error: ${err.message}`);
          debug(`Error: ${JSON.stringify(err.status)} ${JSON.stringify(err.payload)}`);
          assert.ok(err instanceof Error);
        }
      });

      it('Should fail to authenticate the user (Unexpected error in authz service)', async () => {

        const mockPool = mockAgent.get('https://authn');

        // OK from X-server
        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse1);

        // 500 Error from own-auth-api
        mockPool.intercept({path: `/${username}`})
          .reply(HttpStatus.INTERNAL_SERVER_ERROR);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          debug(`Error: ${JSON.stringify(err.status)} ${JSON.stringify(err.message)}`);
          assert.ok(err instanceof Error);
        }
      });
    });
  });
});
