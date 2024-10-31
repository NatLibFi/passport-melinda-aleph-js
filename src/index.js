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
