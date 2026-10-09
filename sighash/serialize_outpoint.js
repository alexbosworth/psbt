const {uint32AsBuffer} = require('./../transactions');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Serialize the outpoint that a transaction input spends

  {
    id: <Spent Transaction Id Hex String>
    vout: <Spent Output Index Number>
  }

  @returns
  <Serialized Outpoint Buffer Object>
*/
module.exports = ({id, vout}) => {
  // Transaction ids are shown reversed from the order that they are hashed in
  const hash = hexAsBuffer(id).reverse();

  return Buffer.concat([hash, uint32AsBuffer({number: vout})]);
};
