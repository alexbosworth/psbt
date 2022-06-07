const decodePsbt = require('./decode_psbt');
const {encodeSignature} = require('./../signatures');
const {script} = require('./../tokens');
const updatePsbt = require('./update_psbt');

/** Combine multiple PSBTs
  {
    ecp: <ECPair Object>
    psbts: [<BIP 174 Encoded PSBT Hex String>]
  }

  @throws
  <Combine PSBT Error>

  @returns
  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }
*/
module.exports = ({ecp, psbts}) => {
  const additionalAttributes = [];
  const globalAttributes = {};
  const inputAttributes = [];
  const outputAttributes = [];
  const [referencePsbt] = psbts;
  const signatures = [];
  const taprootInputs = [];
  let tx;

  psbts.map(psbt => decodePsbt({ecp, psbt})).forEach(decoded => {
    // Transactions must be unique for all combined psbts
    if (!!tx && tx !== decoded.unsigned_transaction) {
      throw new Error('ExpectedUniqueTransaction');
    }

    tx = tx || decoded.unsigned_transaction;

    // Index unknown global attributes for preservation across combines
    (decoded.unrecognized_attributes || []).forEach(({type, value}) => {
      return globalAttributes[type] = value;
    });

    // Iterate through inputs to push signatures, index unknown attributes
    decoded.inputs.forEach((input, vin) => {
      (input.unrecognized_attributes || []).forEach(({type, value}) => {
        inputAttributes[vin] = inputAttributes[vin] || {};

        return inputAttributes[vin][type] = value;
      });

      if (!!input.taproot_key_spend_sig) {
        taprootInputs.push({
          vin,
          key_spend_sig: input.taproot_key_spend_sig,
        });
      }

      return (input.partial_sig || []).forEach(partial => {
        return signatures.push({
          vin,
          hash_type: partial.hash_type,
          public_key: partial.public_key,
          signature: encodeSignature({
            flag: partial.hash_type,
            signature: partial.signature,
          }),
        });
      });
    });

    // Index unrecognized output attributes by vout
    decoded.outputs.forEach((output, vout) => {
      return (output.unrecognized_attributes || []).forEach(pair => {
        outputAttributes[vout] = outputAttributes[vout] || {};

        return outputAttributes[vout][pair.type] = pair.value;
      });
    });

    return;
  });

  // Fold up global unrecognized attributes
  Object.keys(globalAttributes).sort().forEach(type => {
    return additionalAttributes.push({type, value: globalAttributes[type]});
  });

  // Fold up input attributes
  inputAttributes.forEach((attributes, vin) => {
    return Object.keys(attributes).sort().forEach(type => {
      return additionalAttributes.push({type, vin, value: attributes[type]});
    });
  });

  // Fold up output attributes
  outputAttributes.forEach((attributes, vout) => {
    return Object.keys(attributes).sort().forEach(type => {
      return additionalAttributes.push({type, vout, value: attributes[type]});
    });
  });

  try {
    return updatePsbt({
      ecp,
      signatures,
      additional_attributes: additionalAttributes,
      psbt: referencePsbt,
      taproot_inputs: taprootInputs,
    });
  } catch (err) {
    throw err;
  }
};
