import HttpStatus from 'http-status';
import {URL} from 'url';
import {DOMParser, type Document} from '@xmldom/xmldom';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';
import createDebugLogger from 'debug';

const debugDev = createDebugLogger('@natlibfi/passport-melinda-aleph:dev');
const debugDevData = debugDev.extend('data');

export interface AlephOptions {
  xServiceURL: string;
  userLibrary: string;
  ownAuthzURL: string;
  ownAuthzApiKey: string;
}

export interface Name {
  givenName: string;
  familyName: string;
  middleName?: string;
}

/** Contact schema compliant profile: https://tools.ietf.org/html/draft-smarr-vcarddav-portable-contacts-00 */
export interface MelindaUser {
  id: string;
  displayName?: string;
  name?: Name;
  emails?: {value: string, type: 'work'}[];
  organization?: {name: string}[];
  authorization: string[];
}

// eslint-disable-next-line max-lines-per-function
export function createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthzApiKey}: AlephOptions) {
  const xBaseURL = new URL(xServiceURL);

  xBaseURL.searchParams.set('op', 'user-auth');
  xBaseURL.searchParams.set('library', userLibrary);

  return {authenticate};

// eslint-disable-next-line max-lines-per-function
  async function authenticate({username, password}: {username: string, password: string}): Promise<MelindaUser> {
    const requestURL = new URL(xBaseURL);

    requestURL.searchParams.set('staff_user', username);
    requestURL.searchParams.set('staff_pass', password);

    debugDev(`Fetching: ${requestURL}`);
    const response = await fetch(requestURL);
    const body = await response.text();
    debugDevData(`Response (status: ${response.status}): ${JSON.stringify(body)}`);

    if (response.status === HttpStatus.OK) {
      // @xmldom/xmldom v9.0.1
      // 0.9.1: DOMParser.parseFromString requires mimeType as second argument #713
      const doc = new DOMParser().parseFromString(body, 'text/xml');

      checkForErrors(doc);

      const userInfo = parseUserInfo(doc);
      const ownTags = await getOwnTags(username);

      return {...userInfo, authorization: ownTags};
    }

    // This is not tested
    if (response?.headers?.has('WWW-Authenticate')) {
      response.headers.delete('WWW-Authenticate');
      throw new AuthenticationError(response.status, body);
    }

    throw new AuthenticationError(response.status, body);

    function checkForErrors(doc: Document): void {
      if (invalidReply() || hasErrors()) {
        debugDev(`We have some kind of error`)
        throw new AuthenticationError(HttpStatus.BAD_REQUEST, 'X-server authentication error');
      }

      function invalidReply(): boolean {
        // No <reply> element, or first <reply> -element is not "ok"
        const firstReply = doc.getElementsByTagName('reply').item(0);
        return firstReply?.textContent !== 'ok';
      }

      function hasErrors(): boolean {
        // there are <error> elements
        return doc.getElementsByTagName('error').length > 0;
      }
    }

    /* Returns contact schema compliant profile: https://tools.ietf.org/html/draft-smarr-vcarddav-portable-contacts-00 */
    function parseUserInfo(doc: Document): Omit<MelindaUser, 'authorization'> {
      const z66 = doc.getElementsByTagName('z66').item(0);
      if (!z66) {
        debugDev(`We have some kind of error`)
        throw new AuthenticationError(HttpStatus.BAD_REQUEST, 'X-server authentication error');
      }

      const nodeList = z66.childNodes;
      const profile = getData();
      return {...profile, id: username};

      function getData(index = 0, data: Omit<MelindaUser, 'id' | 'authorization'> = {}): Omit<MelindaUser, 'id' | 'authorization'> {
        const node = nodeList.item(index);

        if (!node) {
          return data;
        }

        if (node.nodeName === 'z66-email') {
          return getData(index + 1, {
            ...data,
            emails: [{value: node.textContent ?? '', type: 'work'}]
          });
        }

        if (node.nodeName === 'z66-name') {
          return getData(index + 1, {
            ...data,
            displayName: node.textContent ?? '',
            name: parseName(node.textContent ?? '')
          });

        }

        if (node.nodeName === 'z66-department') {
          return getData(index + 1, {
            ...data,
            organization: [{name: node.textContent ?? ''}]
          });
        }

        return getData(index + 1, data);

        function parseName(value: string): Name {
          const parts = value.split(/ /u);
          debugDev(`parseName: value: ${value}, parts: ${JSON.stringify(parts)}`)
          const obj: Name = {
            givenName: parts[0] ?? '', //first element
            familyName: parts.slice(-1)[0] ?? '' //last element
          };
          //debugDev(`parseName: obj: ${JSON.stringify(obj)}`)

          if (parts.length > 2) {
            const middle = parts.slice(1,-1).join(' '); // elements between first and last
            debugDev(`parseName: middle: ${JSON.stringify(middle)}`);
            return {...obj, middleName: middle};
          }

          return obj;
        }
      }
    }

    async function getOwnTags(username: string): Promise<string[]> {
      const url = new URL(`${ownAuthzURL}/${username}`);
      debugDev(`Fetching OWN tags: ${url}`);
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${ownAuthzApiKey}`,
          Accept: 'application/json'
        }
      });
      debugDevData(`OWN tags response status: ${response.status}`);
      if (response.status !== HttpStatus.OK) {
        throw new Error(`OWN auth API call failed (${response.status}): ${await response.text()}`);
      }

      // External data: validate once at the boundary, then trust the type
      const data: unknown = await response.json();
      if (!isStringArray(data)) {
        throw new Error(`OWN auth API returned an unexpected payload (status: ${response.status})`);
      }

      return data;
    }
  }
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}
