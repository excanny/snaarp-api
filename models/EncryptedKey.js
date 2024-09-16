import { Schema, model } from 'mongoose';

const encryptedKeySchema = new Schema({
  keyId: { type: String, unique: true },
  encryptedValue: String
});

export default model('EncryptedKey', encryptedKeySchema);
