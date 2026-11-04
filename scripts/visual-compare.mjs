import sharp from "sharp";
import fs from "node:fs/promises";
const captures = "docs/ml/phase6/screenshots";
const root = "docs/ml/phase6/visual-comparisons";
await fs.mkdir(root, { recursive: true });
const entries = [
  ["01-dashboard", "dashboard"],
  ["02-analyze-email", "email"],
  ["03-investigations", "investigations"],
];
const measurements = [];
for (const [ref, name] of entries) {
  const source = await sharp(`design-references/${ref}.png`)
    .resize(1672, 941)
    .png()
    .toBuffer();
  const actual = await sharp(`${captures}/${name}-fixture.png`)
    .extract({ left: 0, top: 0, width: 1672, height: 941 })
    .png()
    .toBuffer();
  await sharp({
    create: { width: 3344, height: 941, channels: 3, background: "#020e15" },
  })
    .composite([
      { input: source, left: 0, top: 0 },
      { input: actual, left: 1672, top: 0 },
    ])
    .png()
    .toFile(`${root}/${name}-comparison.png`);
  const a = await sharp(source).removeAlpha().raw().toBuffer(),
    b = await sharp(actual).removeAlpha().raw().toBuffer();
  let sum = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    sum += Math.abs(a[i] - b[i]);
  measurements.push({
    screen: name,
    mean_absolute_channel_difference:
      Math.round((sum / Math.min(a.length, b.length)) * 100) / 100,
    note: "Content and evidence intentionally differ; this is a diagnostic, not an acceptance score.",
  });
}
await fs.writeFile(
  `${root}/pixel-diagnostics.json`,
  JSON.stringify(measurements, null, 2),
);
console.log(
  "Created 3 side-by-side reference comparisons and pixel diagnostics.",
);
