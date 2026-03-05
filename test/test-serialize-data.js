import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import protobuf from 'protobufjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const protoPath = join(__dirname, '../src/utils/proto/telemetry.proto');
const jsonPath = join(__dirname, '../data-output.json');
const outputBinPath = join(__dirname, '../data-reserialized.bin');

const root = await protobuf.load(protoPath);
const TelemetryBatch = root.lookupType('TelemetryBatch');

const jsonData = JSON.parse(readFileSync(jsonPath, 'utf8'));
const message = TelemetryBatch.create(jsonData);
const buffer = TelemetryBatch.encode(message).finish();

writeFileSync(outputBinPath, buffer);
console.log('序列化完成，结果已写入:', outputBinPath);
