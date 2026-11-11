import {BasicStrategy} from 'passport-http';
import {createService, type AlephOptions} from './service.ts';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';

export type {AlephOptions, MelindaUser} from './service.ts';

export class AlephStrategy extends BasicStrategy {
  constructor(options: AlephOptions) {
    const {authenticate} = createService(options);

    super((username, password, done) => {
      authenticate({username, password})
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

    this.name = 'melinda';
  }
}
