const {readCompactSize} = require('./../transactions');

/** Check the standard header of a proprietary key

  {
    key: <Key Buffer Object>
  }

  @throws
  <ExpectedIdentifierInProprietaryKey Error>
  <ExpectedSubtypeInProprietaryKey Error>
*/
module.exports = ({key}) => {
  const type = readCompactSize({encoded: key});

  let identifier;

  // The identifier is a compact size length then that many bytes
  try {
    identifier = readCompactSize({encoded: key, start: type.bytes});
  } catch (err) {
    throw new Error('ExpectedIdentifierInProprietaryKey');
  }

  const start = type.bytes + identifier.bytes;

  if (identifier.number > BigInt(key.length - start)) {
    throw new Error('ExpectedIdentifierInProprietaryKey');
  }

  // The subtype is a compact size number after the identifier
  try {
    readCompactSize({encoded: key, start: start + Number(identifier.number)});
  } catch (err) {
    throw new Error('ExpectedSubtypeInProprietaryKey');
  }

  return;
};
