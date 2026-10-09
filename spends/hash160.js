const {createHash} = require('node:crypto');

/** Hash data with SHA256 and then with RIPEMD160, as public keys are hashed

  {
    data: <Data Buffer Object>
  }

  @returns
  <Hash Buffer Object>
*/
module.exports = ({data}) => {
  const sha256 = createHash('sha256').update(data).digest();

  return createHash('ripemd160').update(sha256).digest();
};
