/* eslint-disable functional/no-this-expressions */
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
import {BasicStrategy} from 'passport-http';
import {createService} from './service';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';

export class AlephStrategy extends BasicStrategy {
  constructor({xServiceURL, userLibrary, ownAuthzURL, ownAuthzApiKey}) {
    const AuthenticationService = createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthzApiKey});

    super((username, password, done) => {
      AuthenticationService.authenticate({username, password})
        .then(user => {
          done(null, user);
        })
        .catch(err => {
          if (err instanceof AuthenticationError) {
            done(null, false);
            return;
          }

          done(err);
        });
    });

    this.name = 'melinda'; // eslint-disable-line functional/no-this-expressions
  }
}
