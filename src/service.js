import HttpStatus from 'http-status';
import {URL} from 'url';
import {DOMParser} from '@xmldom/xmldom';
import {Error as AuthenticationError} from '@natlibfi/melinda-commons';
import createDebugLogger from 'debug';

const debugDev = createDebugLogger('@natlibfi/passport-melinda-aleph:dev');
const debugDevData = debugDev.extend('data');

export function createService({xServiceURL, userLibrary, ownAuthzURL, ownAuthzApiKey}) {
  const xBaseURL = new URL(xServiceURL);

  xBaseURL.searchParams.set('op', 'user-auth');
  xBaseURL.searchParams.set('library', userLibrary);

  return {authenticate};

  // eslint-disable-next-line max-statements
  async function authenticate({username, password}) {
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

    if (response?.headers?.has('WWW-Authenticate')) {
      response.headers.delete('WWW-Authenticate');
      throw new AuthenticationError(response.status, body);
    }

    throw new AuthenticationError(response.status, body);

    function checkForErrors(doc) {
      if (invalidReply() || hasErrors()) {
        throw new AuthenticationError(400, body);
      }

      function invalidReply() {
        const nodeList = doc.getElementsByTagName('reply');
        return nodeList.length === 0 ? true : nodeList.length > 0 && nodeList.item(0).textContent !== 'ok';
      }

      function hasErrors() {
        return doc.getElementsByTagName('error').length > 0;
      }
    }

    /* Returns contact schema compliant profile: https://tools.ietf.org/html/draft-smarr-vcarddav-portable-contacts-00 */
    function parseUserInfo(doc) {
      const nodeList = doc.getElementsByTagName('z66').item(0).childNodes;
      return {...getData(), id: username};

      function getData(index = 0, data = {}) {
        const node = nodeList.item(index);

        if (node) {
          if (node.nodeName === 'z66-email') {
            return getData(index + 1, {
              ...data,
              emails: [{value: node.textContent, type: 'work'}]
            });
          }

          if (node.nodeName === 'z66-name') {
            return getData(index + 1, {
              ...data,
              displayName: node.textContent,
              name: parseName(node.textContent)
            });

          }

          if (node.nodeName === 'z66-department') {
            return getData(index + 1, {
              ...data,
              organization: [{name: node.textContent}]
            });
          }

          return getData(index + 1, data);
        }

        return data;

        function parseName(value) {
          const parts = value.split(/ /u);
          const obj = {
            givenName: parts[0],
            familyName: parts.slice(-1)[0]
          };

          if (parts.length > 2) {
            return {...obj, middleName: parts.slice(2).join(' ')};
          }

          return obj;
        }
      }
    }

    async function getOwnTags(username) {
      const url = new URL(`${ownAuthzURL}/${username}`);
      debugDev(`Fetching: ${url}`);
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${ownAuthzApiKey}`,
          Accept: 'application/json'
        }
      });
      debugDevData(`Response status: ${response.status}`);
      if (response.status === HttpStatus.OK) {
        return response.json();
      }

      throw new Error(`OWN auth API call failed: ${await response.text()}`);
    }
  }
}
