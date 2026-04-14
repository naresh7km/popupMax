const fs = require("fs");
const path = require("path");
const {
  AmplifyClient,
  CreateAppCommand,
  DeleteAppCommand,
  CreateBranchCommand,
  UpdateAppCommand,
} = require("@aws-sdk/client-amplify");
const {
  WAFV2Client,
  ListWebACLsCommand,
} = require("@aws-sdk/client-wafv2");
const simpleGit = require("simple-git");

const REGION = "ap-northeast-1";
const APP_PREFIX = "dmc";
const MAX_APPS = 4;

const TARGET_ORIGIN =
  "https://kotonohaschooljpnew.d2iebmp9qpa7oy.amplifyapp.com";

const amplify = new AmplifyClient({ region: REGION });
const waf = new WAFV2Client({ region: "us-east-1" });

const appsFile = path.join(__dirname, "../apps.json");

function loadApps() {
  return JSON.parse(fs.readFileSync(appsFile, "utf-8"));
}

function saveApps(data) {
  fs.writeFileSync(appsFile, JSON.stringify(data, null, 2));
}

async function getWafArn() {
  const res = await waf.send(
    new ListWebACLsCommand({ Scope: "CLOUDFRONT" })
  );

  const found = res.WebACLs.find((w) =>
    w.Name.includes("CreatedByAmplify")
  );

  if (!found) throw new Error("WAF not found");

  return found.ARN;
}

function getNextName(apps) {
  return APP_PREFIX + (apps.length + 1);
}

// ✅ FIXED (no IAM role, no buildSpec)
async function createApp(name) {
  const res = await amplify.send(
    new CreateAppCommand({
      name,
      repository: "https://github.com/naresh7km/popupMax",
      accessToken: process.env.AMPLIFY_GITHUB_TOKEN,
      platform: "WEB"
    })
  );
  return res.app;
}

async function createBranch(appId) {
  await amplify.send(
    new CreateBranchCommand({
      appId,
      branchName: "main",
    })
  );
}

async function attachWaf(appId, wafArn) {
  await amplify.send(
    new UpdateAppCommand({
      appId,
      webAclArn: wafArn,
    })
  );
}

function updateIndex(newUrl) {
  const file = path.join(__dirname, "../index.js");
  let content = fs.readFileSync(file, "utf-8");

  const pattern = new RegExp(
    `("${TARGET_ORIGIN}"\\s*:\\s*{\\s*redirectURL:\\s*")([^"]*)(")`,
    "s"
  );

  content = content.replace(pattern, `$1${newUrl}$3`);

  fs.writeFileSync(file, content);
}

async function pushChanges() {
  const git = simpleGit();
  await git.add(".");
  await git.commit("auto update amplify url");
  await git.push();
}

async function deleteOldest(apps) {
  if (apps.length <= MAX_APPS) return apps;

  const oldest = apps.shift();

  await amplify.send(
    new DeleteAppCommand({
      appId: oldest.id,
    })
  );

  return apps;
}

(async () => {
  try {
    let apps = loadApps();

    const name = getNextName(apps);

    const app = await createApp(name);

    await createBranch(app.appId);

    const wafArn = await getWafArn();
    await attachWaf(app.appId, wafArn);

    const url = `https://main.${app.defaultDomain}`;

    updateIndex(url);
    await pushChanges();

    apps.push({ id: app.appId, name });

    apps = await deleteOldest(apps);

    saveApps(apps);

    console.log("DONE:", name, url);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
})();
