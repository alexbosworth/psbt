const {createHash} = require('node:crypto');

/** Hash data twice with SHA256, as transactions and signatures are hashed

  {
    data: <Data Buffer Object>
  }

  @returns
  <Hash Buffer Object>
*/
module.exports = ({data}) => {
  const once = createHash('sha256').update(data).digest();

  return createHash('sha256').update(once).digest();
};
