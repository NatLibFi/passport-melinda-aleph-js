import fs from 'fs';
import path from 'path';
import {expect} from 'chai';
import HttpStatus from 'http-status';
import * as testContext from './service';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';
import {Agent, MockAgent, setGlobalDispatcher} from 'undici';
import createDebugLogger from 'debug';

const debug = createDebugLogger('@natlibfi/passport-melinda-aleph:test');

const FIXTURES_PATH = path.join(__dirname, '../test-fixtures/authentication');
const authnResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse1.xml'), 'utf8');
const authnResponse2 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse2.xml'), 'utf8');
const authnResponse3 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse3.xml'), 'utf8');
const authzResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authzResponse1.json'), 'utf8');
const userData1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'userData1.json'), 'utf8');

const mockAgent = new MockAgent();

describe('authentication/service', () => {
  describe('factory', () => {
    it('Should create the expected object', () => {
      const service = testContext.createService({xServiceURL: 'https://authn', userLibrary: 'foo'});
      expect(service).to.be.an('object').and.respondTo('authenticate');
    });

    describe('#authenticate', () => {

      before(() => {
        debug(`before`);
        setGlobalDispatcher(mockAgent);
        mockAgent.disableNetConnect();
      });

      after(async () => {
        debug(`after`);
        await mockAgent.close();
        setGlobalDispatcher(new Agent());
      });

      it('Should authenticate the user succesfully', async () => {
        debug(`TEST`);

        // We have same URL for both services, so that undici mock can interrupt both calls
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authn';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        const mockPool = mockAgent.get('https://authn');

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar
        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse1);

        // https://authn/foo
        mockPool.intercept({path: `/${username}`})
          .reply(HttpStatus.OK, authzResponse1);

        debug(`Testing`);
        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});
        const user = await service.authenticate({username, password});

        expect(user).to.eql(JSON.parse(userData1));
      });

      it('Should fail to authenticate the user (Invalid credentials)', async () => {

        // We have same URL for both services, so that undici mock can interrupt both calls
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authn';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse2);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          //debug(`Error: ${err.message}`);
          expect(err).to.be.an.instanceof(AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Reply not ok)', async () => {
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authn';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse3);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          //debug(`Error: ${err.message}`);
          expect(err).to.be.an.instanceof(AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Unexpected error)', async () => {

        // We have same URL for both services, so that undici mock can interrupt both calls
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authn';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(500);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          //debug(`Error: ${err.message}`);
          expect(err).to.be.an('error');
        }
      });

      it('Should fail to authenticate the user (Unexpected error in authz service)', async () => {

        // We have same URL for both services, so that undici mock can interrupt both calls
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authn';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        const mockPool = mockAgent.get('https://authn');

        mockPool.intercept({path: `/?op=user-auth&library=${userLibrary}&staff_user=${username}&staff_pass=${password}`})
          .reply(200, authnResponse1);

        mockPool.intercept({path: `/${username}`})
          .reply(HttpStatus.INTERNAL_SERVER_ERROR);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          //debug(`Error: ${err.message}`);
          expect(err).to.be.an('error');
        }
      });
    });
  });
});
