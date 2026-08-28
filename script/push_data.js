const {OP_PUSHDATA1} = require('bitcoin-ops');
const {OP_PUSHDATA2} = require('bitcoin-ops');
const {OP_PUSHDATA4} = require('bitcoin-ops');
const pushdata = require('pushdata-bitcoin');


/** Get a push data buffer for data to push on the stack

  {
    [data]: <Data to Encode in Push Data Buffer>
    [encode]: <Data to Encode In Push Data Hex String>
  }

  @throws
  <Encode Data As Push Data Error>

  @returns
  <Push Data Buffer>
*/
module.exports = ({data, encode}) => {
  const dataToEncode = data || Buffer.from(encode, 'hex');

  const dataLength = dataToEncode.length;

  switch (Buffer.alloc(pushdata.encodingLength(dataLength)).length) {
  case 1:
    return Buffer.concat([Buffer.from([dataLength]), dataToEncode]);

  case 2:
    return Buffer.concat([
      Buffer.from([OP_PUSHDATA1, dataLength]),
      dataToEncode,
    ]);

  case 3: {
    const encodedLength = Buffer.alloc(2);

    encodedLength.writeUInt16LE(dataLength);

    return Buffer.concat([
      Buffer.from([OP_PUSHDATA2]),
      encodedLength,
      dataToEncode,
    ]);
  }

  default: {
    const encodedLength = Buffer.alloc(4);

    encodedLength.writeUInt32LE(dataLength);

    return Buffer.concat([
      Buffer.from([OP_PUSHDATA4]),
      encodedLength,
      dataToEncode,
    ]);
  }
  }
};
