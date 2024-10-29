/* eslint-disable no-console */
/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Passport authentication strategy for Melinda using Aleph credentials
*
* Copyright (C) 2018-2022 University Of Helsinki (The National Library Of Finland)
*
* This file is part of passport-melinda-aleph-js
*
* passport-melinda-aleph-js program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* passport-melinda-aleph-js is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this file.
*
*/

import fs from 'fs';
import path from 'path';
import {expect} from 'chai';
import HttpStatus from 'http-status';
import nock from 'nock';
import * as testContext from './service';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';
//import {createDebugLogger} from 'debug';

//const debug = createDebugLogger('@natlibfi/passport-melinda-aleph:test');

const FIXTURES_PATH = path.join(__dirname, '../test-fixtures/authentication');
const authnResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse1.xml'), 'utf8');
const authnResponse2 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse2.xml'), 'utf8');
const authnResponse3 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authnResponse3.xml'), 'utf8');
const authzResponse1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'authzResponse1.json'), 'utf8');
const userData1 = fs.readFileSync(path.resolve(FIXTURES_PATH, 'userData1.json'), 'utf8');

describe('authentication/service', () => {
  describe('factory', () => {
    it('Should create the expected object', () => {
      const service = testContext.createService({xServiceURL: 'https://auth', userLibrary: 'foo'});
      expect(service).to.be.an('object').and.respondTo('authenticate');
    });

    describe('#authenticate', () => {
      afterEach(() => {
        nock.cleanAll();
      });

      it('Should authenticate the user succesfully', async () => {
        console.log(`FOOBAR`);
        const xServiceURL = 'https://aleph-x-proxy.melinda-test.kansalliskirjasto.fi/X';
        const ownAuthzURL = 'https://authz';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar
        nock('https://aleph-x-proxy.melinda-test.kansalliskirjasto.fi/X')
          .get('/')
          .query({
            op: 'user-auth', library: userLibrary,
            staff_user: username, staff_pass: password // eslint-disable-line camelcase
          })
          .reply(HttpStatus.OK, authnResponse1);

        nock('https://authz')
          .get(`/${username}`)
          .reply(HttpStatus.OK, authzResponse1);

        //debug(`Testing`);
        // eslint-disable-next-line no-console
        console.log(`Testing`);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});
        const user = await service.authenticate({username, password});

        expect(user).to.eql(JSON.parse(userData1));
      });

      it('Should fail to authenticate the user (Invalid credentials)', async () => {
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authz';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        // https://authn/?op=user-auth&library=foo&staff_user=foo&staff_pass=bar
        nock('https://authn')
          .get('/')
          .query({
            op: 'user-auth', library: userLibrary,
            staff_user: username, staff_pass: password // eslint-disable-line camelcase
          })
          .reply(HttpStatus.OK, authnResponse2);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          expect(err).to.be.an.instanceof(AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Reply not ok)', async () => {
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authz';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        nock('https://authn')
          .get('/')
          .query({
            op: 'user-auth', library: userLibrary,
            staff_user: username, staff_pass: password // eslint-disable-line camelcase
          })
          .reply(HttpStatus.OK, authnResponse3);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          expect(err).to.be.an.instanceof(AuthenticationError);
        }
      });

      it('Should fail to authenticate the user (Unexpected error)', async () => {
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authz';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        nock('https://authn')
          .get('/')
          .query({
            op: 'user-auth', library: userLibrary,
            staff_user: username, staff_pass: password // eslint-disable-line camelcase
          })
          .reply(HttpStatus.INTERNAL_SERVER_ERROR);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          expect(err).to.be.an('error');
        }
      });

      it('Should fail to authenticate the user (Unexpected error in authz service)', async () => {
        const xServiceURL = 'https://authn';
        const ownAuthzURL = 'https://authz';
        const ownAuthApiKey = 'foobar';
        const userLibrary = 'foo';
        const username = 'foo';
        const password = 'bar';

        nock('https://authn')
          .get('/')
          .query({
            op: 'user-auth', library: userLibrary,
            staff_user: username, staff_pass: password // eslint-disable-line camelcase
          })
          .reply(HttpStatus.OK, authnResponse1);

        nock('https://authz')
          .get(`/${username}`)
          .reply(HttpStatus.INTERNAL_SERVER_ERROR);

        const service = testContext.createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthApiKey});

        try {
          await service.authenticate({username, password});
          throw new Error('Should throw');
        } catch (err) {
          expect(err).to.be.an('error');
        }
      });
    });
  });
});
