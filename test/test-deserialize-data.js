import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import protobuf from 'protobufjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const protoPath = join(__dirname, '../src/utils/proto/telemetry.proto');
const dataBinPath = join(__dirname, '../data.bin');
const outputPath = join(__dirname, '../data-output.json');

const root = await protobuf.load(protoPath);
const TelemetryBatch = root.lookupType('TelemetryBatch');

const buffer = readFileSync(dataBinPath);
const message = TelemetryBatch.decode(buffer);
const object = TelemetryBatch.toObject(message, { longs: String, enums: String, bytes: String });

writeFileSync(outputPath, JSON.stringify(object, null, 2));
console.log('反序列化完成，结果已写入:', outputPath);
