import ReactDOM from "react-dom";
import React, { Component } from "react";
import {
  Box,
  Button,
  Checkbox,
  CssBaseline,
  FormControlLabel,
  Paper,
  TextField,
  Typography,
  withStyles,
} from "@material-ui/core";
import { Close as CloseIcon, Check as CheckIcon } from "@material-ui/icons";
import { fromHex, toHex } from "uint8array-tools";

import * as _secp256k1 from "../../lib/index.js";
import { generate } from "../random-in-node/index.js";

const EMPTY_BUFFER = new Uint8Array(0);
function toUint8Array(value) {
  if (typeof value !== "string") return value;
  if (value.match(/^\d{1,20}$/)) return parseInt(value);
  const data = fromHex(value);
  return toHex(data) === value ? data : EMPTY_BUFFER;
}

const validate = {
  isTweak: (value) => _secp256k1.isPrivate(toUint8Array(value)),
  isHash(value) {
    const hash = toUint8Array(value);
    return hash instanceof Uint8Array && hash.length === 32;
  },
  isExtraData(value) {
    const entropy = toUint8Array(value);
    return (
      entropy === undefined ||
      (entropy instanceof Uint8Array && entropy.length === 32)
    );
  },
  isSignature(value) {
    const signature = toUint8Array(value);
    return (
      signature instanceof Uint8Array &&
      signature.length === 64 &&
      _secp256k1.isPrivate(signature.slice(0, 32)) &&
      _secp256k1.isPrivate(signature.slice(32, 64))
    );
  },
  isParity(parity) {
    return parity === 1 || parity === 0;
  },
};
const secp256k1 = {
  _throw2null(method, args) {
    try {
      let result = _secp256k1[method](...args.map((v) => toUint8Array(v)));
      if (result instanceof Uint8Array) {
        result = toHex(result);
      }
      return result;
    } catch (_err) {
      return null;
    }
  },
};
for (const method of Object.keys(_secp256k1)) {
  secp256k1[method] = (...args) => secp256k1._throw2null(method, args);
}

const useStyles = (theme) => ({
  layout: {
    width: "auto",
    marginLeft: theme.spacing(2),
    marginRight: theme.spacing(2),
    [theme.breakpoints.up(1200 + theme.spacing(2) * 2)]: {
      width: 1200,
      marginLeft: "auto",
      marginRight: "auto",
    },
  },
  paper: {
    marginTop: theme.spacing(3),
    marginBottom: theme.spacing(3),
    padding: theme.spacing(2),
    [theme.breakpoints.up(1200 + theme.spacing(3) * 2)]: {
      marginTop: theme.spacing(6),
      marginBottom: theme.spacing(6),
      padding: theme.spacing(3),
    },
  },
  methodBox: {
    marginTop: theme.spacing(5),
  },
  rootError: {
    "& $notchedOutline": {
      borderColor: theme.palette.error.main,
    },
    "&:hover $notchedOutline": {
      borderColor: theme.palette.error.main,
    },
    "&$focused $notchedOutline": {
      borderColor: theme.palette.error.main,
    },
  },
  rootSuccess: {
    "& $notchedOutline": {
      borderColor: theme.palette.success.main,
    },
    "&:hover $notchedOutline": {
      borderColor: theme.palette.success.main,
    },
    "&$focused $notchedOutline": {
      borderColor: theme.palette.success.main,
    },
  },
  focused: {},
  notchedOutline: {},
});

function getInputProps(valid, styles) {
  return {
    classes: {
      root:
        valid === undefined
          ? undefined
          : valid
          ? styles.rootSuccess
          : styles.rootError,
      focused: styles.focused,
      notchedOutline: styles.notchedOutline,
    },
  };
}

const createInputChange = (self, name) => (event) =>
  self.setState({ [name]: event.target.value });
const createCheckedChange = (self, name) => (event) =>
  self.setState({ [name]: event.target.checked });

const CompressedCheckbox = withStyles({
  root: {
    color: "#64b5f6",
    "&$checked": {
      color: "#64b5f6",
    },
  },
  checked: {},
})((props) => <Checkbox color="default" {...props} />);

const App = withStyles(useStyles)(
  class App extends Component {
    constructor(props) {
      super(props);
      this.onGenerate = this.onGenerate.bind(this);
      this.state = { data: {} };
    }

    onGenerate() {
      const data = generate();
      for (const key of Object.keys(data)) {
        if (data[key] instanceof Uint8Array) {
          data[key] = toHex(data[key]);
        } else if (typeof data[key] === "number") {
          data[key] = data[key].toString(10);
        }
      }
      this.setState({ data });
    }

    render() {
      return (
        <>
          <CssBaseline />
          <main className={this.props.classes.layout}>
            <Paper className={this.props.classes.paper}>
              <Box align="center">
                <Button
                  variant="contained"
                  color="primary"
                  onClick={this.onGenerate}
                >
                  generate data
                </Button>
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiIsPoint
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey_uncompressed}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiIsPointCompressed
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiIsPrivate
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPointAdd
                  classes={this.props.classes}
                  pubkey1={this.state.data?.pubkey}
                  pubkey2={this.state.data?.pubkey2}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPointAddScalar
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey}
                  tweak={this.state.data?.tweak}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPointCompress
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPointFromScalar
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiXOnlyPointFromScalar
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiXOnlyPointFromPoint
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiXOnlyPointAddTweak
                  classes={this.props.classes}
                  x_only_pubkey={this.state.data?.x_only_pubkey}
                  x_only_pubkey2={this.state.data?.x_only_pubkey2}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiXOnlyPointAddTweakCheck
                  classes={this.props.classes}
                  x_only_pubkey={this.state.data?.x_only_pubkey}
                  x_only_add_tweak={this.state.data?.x_only_add_tweak}
                  x_only_pubkey2={this.state.data?.x_only_pubkey2}
                  x_only_add_parity={this.state.data?.x_only_add_parity}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPointMultiply
                  classes={this.props.classes}
                  pubkey={this.state.data?.pubkey}
                  tweak={this.state.data?.tweak}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPrivateAdd
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                  tweak={this.state.data?.tweak}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPrivateSub
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                  tweak={this.state.data?.tweak}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiPrivateNegate
                  classes={this.props.classes}
                  seckey={this.state.data?.seckey}
                  tweak={this.state.data?.tweak}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiSign
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  seckey={this.state.data?.seckey}
                  entropy={this.state.data?.entropy}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiSignRecoverable
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  seckey={this.state.data?.seckey}
                  entropy={this.state.data?.entropy}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiVerify
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  pubkey={this.state.data?.pubkey}
                  signature={this.state.data?.signature}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiRecover
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  signature={this.state.data?.signature}
                  recoveryId={this.state.data?.recoveryId}
                  compressed={this.state.data?.compressed}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiSignSchnorr
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  seckey={this.state.data?.seckey}
                  entropy={this.state.data?.entropy}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiVerifySchnorr
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  x_only_pubkey={this.state.data?.x_only_pubkey}
                  schnorr_signature={this.state.data?.schnorr_signature}
                />
              </Box>
            </Paper>
          </main>
        </>
      );
    }
  }
);

const createApiIsPoint = (name) =>
  withStyles(useStyles)(
    class extends Component {
      constructor(props) {
        super(props);
        this.state = { pubkey: "", valid: undefined };
      }

      componentDidUpdate(prevProps, prevState) {
        if (prevProps.pubkey !== this.props.pubkey) {
          this.setState({ pubkey: this.props.pubkey });
        }
        if (prevState.pubkey !== this.state.pubkey) {
          const value = this.state.pubkey;
          const valid = value === "" ? undefined : secp256k1[name](value);
          this.setState({ valid });
        }
      }

      render() {
        return (
          <>
            <Typography variant="h6">
              {name}(p: Uint8Array) =&gt; boolean
            </Typography>
            <TextField
              label="Public Key as HEX string"
              onChange={createInputChange(this, "pubkey")}
              value={this.state.pubkey}
              fullWidth
              margin="normal"
              variant="outlined"
              InputProps={getInputProps(this.state.valid, this.props.classes)}
            />
          </>
        );
      }
    }
  );

const ApiIsPoint = createApiIsPoint("isPoint");
const ApiIsPointCompressed = createApiIsPoint("isPointCompressed");

const ApiIsPrivate = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = { seckey: "", valid: undefined };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.seckey !== this.props.seckey) {
        this.setState({ seckey: this.props.seckey });
      }
      if (prevState.seckey !== this.state.seckey) {
        const value = this.state.seckey;
        const valid = value === "" ? undefined : secp256k1.isPrivate(value);
        this.setState({ valid });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            isPrivate(d: Uint8Array) =&gt; boolean
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.valid, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPointAdd = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        pubkey1: "",
        pubkey1_valid: undefined,
        pubkey2: "",
        pubkey2_valid: undefined,
        compressed: true,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.pubkey1 !== this.props.pubkey1 ||
        prevProps.pubkey2 !== this.props.pubkey2
      ) {
        this.setState({
          pubkey1: this.props.pubkey1,
          pubkey2: this.props.pubkey2,
        });
      }

      if (
        prevState.pubkey1 !== this.state.pubkey1 ||
        prevState.pubkey2 !== this.state.pubkey2 ||
        prevState.compressed !== this.state.compressed
      ) {
        const { pubkey1, pubkey2 } = this.state;
        const pubkey1_valid =
          pubkey1 === "" ? undefined : secp256k1.isPoint(pubkey1);
        const pubkey2_valid =
          pubkey2 === "" ? undefined : secp256k1.isPoint(pubkey2);
        const result =
          pubkey1 === "" && pubkey2 === ""
            ? undefined
            : secp256k1.pointAdd(pubkey1, pubkey2, this.state.compressed);
        this.setState({ pubkey1_valid, pubkey2_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            pointAdd(pA: Uint8Array, pB: Uint8Array, compressed?: boolean) =&gt;
            Uint8Array | null
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey1")}
            value={this.state.pubkey1}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey1_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey2")}
            value={this.state.pubkey2}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey2_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPointAddScalar = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        pubkey: "",
        pubkey_valid: undefined,
        tweak: "",
        tweak_valid: undefined,
        compressed: true,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.pubkey !== this.props.pubkey ||
        prevProps.tweak !== this.props.tweak
      ) {
        this.setState({
          pubkey: this.props.pubkey,
          tweak: this.props.tweak,
        });
      }

      if (
        prevState.pubkey !== this.state.pubkey ||
        prevState.tweak !== this.state.tweak ||
        prevState.compressed !== this.state.compressed
      ) {
        const { pubkey, tweak } = this.state;
        const pubkey_valid =
          pubkey === "" ? undefined : secp256k1.isPoint(pubkey);
        const tweak_valid = tweak === "" ? undefined : validate.isTweak(tweak);
        const result =
          pubkey === "" && tweak === ""
            ? undefined
            : secp256k1.pointAddScalar(pubkey, tweak, this.state.compressed);
        this.setState({ pubkey_valid, tweak_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            pointAddScalar(p: Uint8Array, tweak: Uint8Array, compressed?:
            boolean) =&gt; Uint8Array | null
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey")}
            value={this.state.pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweak as HEX string"
            onChange={createInputChange(this, "tweak")}
            value={this.state.tweak}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.tweak_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPointCompress = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        pubkey: "",
        pubkey_valid: undefined,
        compressed: true,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.pubkey !== this.props.pubkey) {
        this.setState({
          pubkey: this.props.pubkey,
        });
      }

      if (
        prevState.pubkey !== this.state.pubkey ||
        prevState.compressed !== this.state.compressed
      ) {
        const { pubkey } = this.state;
        const pubkey_valid =
          pubkey === "" ? undefined : secp256k1.isPoint(pubkey);
        const result =
          pubkey === ""
            ? undefined
            : secp256k1.pointCompress(pubkey, this.state.compressed);
        this.setState({ pubkey_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            pointCompress(p: Uint8Array, compressed?: boolean) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey")}
            value={this.state.pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPointFromScalar = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        seckey: "",
        compressed: true,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.seckey !== this.props.seckey) {
        this.setState({
          seckey: this.props.seckey,
        });
      }

      if (
        prevState.seckey !== this.state.seckey ||
        prevState.compressed !== this.state.compressed
      ) {
        const { seckey } = this.state;
        const result =
          seckey === ""
            ? undefined
            : secp256k1.pointFromScalar(seckey, this.state.compressed);
        this.setState({ result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            pointFromScalar(d: Uint8Array, compressed?: boolean) =&gt;
            Uint8Array | null
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiXOnlyPointFromScalar = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        seckey: "",
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.seckey !== this.props.seckey) {
        this.setState({
          seckey: this.props.seckey,
        });
      }

      if (prevState.seckey !== this.state.seckey) {
        const { seckey } = this.state;
        const result =
          seckey === "" ? undefined : secp256k1.xOnlyPointFromScalar(seckey);
        this.setState({ result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            xOnlyPointFromScalar(d: Uint8Array) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiXOnlyPointFromPoint = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        pubkey: "",
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.pubkey !== this.props.pubkey) {
        this.setState({
          pubkey: this.props.pubkey,
        });
      }

      if (prevState.pubkey !== this.state.pubkey) {
        const { pubkey } = this.state;
        const result =
          pubkey === "" ? undefined : secp256k1.xOnlyPointFromPoint(pubkey);
        this.setState({ result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            xOnlyPointFromPoint(p: Uint8Array) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey")}
            value={this.state.pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiXOnlyPointAddTweak = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        x_only_pubkey: "",
        x_only_pubkey2: "",
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.x_only_pubkey !== this.props.x_only_pubkey ||
        prevProps.x_only_pubkey2 !== this.props.x_only_pubkey2
      ) {
        this.setState({
          x_only_pubkey: this.props.x_only_pubkey,
          x_only_pubkey2: this.props.x_only_pubkey2,
        });
      }

      if (
        prevState.x_only_pubkey !== this.state.x_only_pubkey ||
        prevState.x_only_pubkey2 !== this.state.x_only_pubkey2
      ) {
        const { x_only_pubkey, x_only_pubkey2 } = this.state;
        const output =
          x_only_pubkey === "" || x_only_pubkey2 === ""
            ? undefined
            : secp256k1.xOnlyPointAddTweak(x_only_pubkey, x_only_pubkey2);
        this.setState({
          result: toHex(output.xOnlyPubkey),
        });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            xOnlyPointAddTweak(p: Uint8Array, p2: Uint8Array) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "x_only_pubkey")}
            value={this.state.x_only_pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <TextField
            label="Tweak Key as HEX string"
            onChange={createInputChange(this, "x_only_pubkey2")}
            value={this.state.x_only_pubkey2}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <TextField
            label="Output, Tweaked Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiXOnlyPointAddTweakCheck = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        x_only_pubkey: "",
        x_only_pubkey_valid: undefined,
        x_only_pubkey2: "",
        x_only_pubkey2_valid: undefined,
        x_only_add_tweak: "",
        x_only_add_tweak_valid: undefined,
        x_only_add_parity: "",
        x_only_add_parity_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.x_only_pubkey !== this.props.x_only_pubkey ||
        prevProps.x_only_add_tweak !== this.props.x_only_add_tweak ||
        prevProps.x_only_pubkey2 !== this.props.x_only_pubkey2 ||
        prevProps.x_only_add_parity !== this.props.x_only_add_parity
      ) {
        this.setState({
          x_only_pubkey: this.props.x_only_pubkey,
          x_only_add_tweak: this.props.x_only_add_tweak,
          x_only_pubkey2: this.props.x_only_pubkey2,
          x_only_add_parity: this.props.x_only_add_parity,
        });
      }

      if (
        prevState.x_only_pubkey !== this.state.x_only_pubkey ||
        prevState.x_only_add_tweak !== this.state.x_only_add_tweak ||
        prevState.x_only_pubkey2 !== this.state.x_only_pubkey2 ||
        prevState.x_only_add_parity !== this.state.x_only_add_parity
      ) {
        const {
          x_only_pubkey,
          x_only_add_tweak,
          x_only_pubkey2,
          x_only_add_parity,
        } = this.state;
        const x_only_pubkey_valid =
          x_only_pubkey === ""
            ? undefined
            : secp256k1.isXOnlyPoint(x_only_pubkey);
        const x_only_pubkey2_valid =
          x_only_pubkey2 === ""
            ? undefined
            : secp256k1.isXOnlyPoint(x_only_pubkey2);
        const x_only_add_tweak_valid =
          x_only_add_tweak === ""
            ? undefined
            : secp256k1.isXOnlyPoint(x_only_add_tweak);
        const x_only_add_parity_valid =
          x_only_add_parity === ""
            ? undefined
            : validate.isParity(parseInt(x_only_add_parity));
        const result =
          x_only_pubkey_valid === "" &&
          x_only_pubkey2_valid === "" &&
          x_only_add_tweak_valid === "" &&
          x_only_add_parity_valid === ""
            ? undefined
            : secp256k1.xOnlyPointAddTweakCheck(
                x_only_pubkey,
                x_only_pubkey2,
                x_only_add_tweak,
                x_only_add_parity
              );
        this.setState({
          x_only_pubkey_valid,
          x_only_pubkey2_valid,
          x_only_add_tweak_valid,
          x_only_add_parity_valid,
          result,
        });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            xOnlyPointAddTweakCheck(p1: Uint8Array, tweak: Uint8Array, p2:
            Uint8Array, parity: 1 | 0) =&gt; boolean
          </Typography>
          <TextField
            label="xOnlyPublicKey as HEX string"
            onChange={createInputChange(this, "x_only_pubkey")}
            value={this.state.x_only_pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.x_only_pubkey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweak Key as HEX string"
            onChange={createInputChange(this, "x_only_pubkey2")}
            value={this.state.x_only_pubkey2}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.x_only_pubkey2_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweaked Key as HEX string"
            onChange={createInputChange(this, "x_only_add_tweak")}
            value={this.state.x_only_add_tweak}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.x_only_add_tweak_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Parity bit as 1 or 0"
            onChange={createInputChange(this, "x_only_add_parity")}
            value={this.state.x_only_add_parity}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.x_only_add_parity_valid,
              this.props.classes
            )}
          />
          {this.state.result !== undefined && (
            <Box align="center">
              {this.state.result === true ? (
                <CheckIcon />
              ) : (
                <CloseIcon color="error" />
              )}
            </Box>
          )}
        </>
      );
    }
  }
);

const ApiPointMultiply = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        pubkey: "",
        pubkey_valid: undefined,
        tweak: "",
        tweak_valid: undefined,
        compressed: true,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.pubkey !== this.props.pubkey ||
        prevProps.tweak !== this.props.tweak
      ) {
        this.setState({
          pubkey: this.props.pubkey,
          tweak: this.props.tweak,
        });
      }

      if (
        prevState.pubkey !== this.state.pubkey ||
        prevState.tweak !== this.state.tweak ||
        prevState.compressed !== this.state.compressed
      ) {
        const { pubkey, tweak } = this.state;
        const pubkey_valid =
          pubkey === "" ? undefined : secp256k1.isPoint(pubkey);
        const tweak_valid = tweak === "" ? undefined : validate.isTweak(tweak);
        const result =
          pubkey === "" && tweak === ""
            ? undefined
            : secp256k1.pointMultiply(pubkey, tweak, this.state.compressed);
        this.setState({ pubkey_valid, tweak_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            pointMultiply(p: Uint8Array, tweak: Uint8Array, compressed?:
            boolean) =&gt; Uint8Array | null
          </Typography>
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey")}
            value={this.state.pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweak as HEX string"
            onChange={createInputChange(this, "tweak")}
            value={this.state.tweak}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.tweak_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPrivateAdd = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        seckey: "",
        seckey_valid: undefined,
        tweak: "",
        tweak_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.seckey !== this.props.seckey ||
        prevProps.tweak !== this.props.tweak
      ) {
        this.setState({
          seckey: this.props.seckey,
          tweak: this.props.tweak,
        });
      }

      if (
        prevState.seckey !== this.state.seckey ||
        prevState.tweak !== this.state.tweak
      ) {
        const { seckey, tweak } = this.state;
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const tweak_valid = tweak === "" ? undefined : validate.isTweak(tweak);
        const result =
          seckey === "" && tweak === ""
            ? undefined
            : secp256k1.privateAdd(seckey, tweak);
        this.setState({ seckey_valid, tweak_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            privateAdd(d: Uint8Array, tweak: Uint8Array) =&gt; Uint8Array | null
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweak as HEX string"
            onChange={createInputChange(this, "tweak")}
            value={this.state.tweak}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.tweak_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Output, Private Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPrivateSub = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        seckey: "",
        seckey_valid: undefined,
        tweak: "",
        tweak_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.seckey !== this.props.seckey ||
        prevProps.tweak !== this.props.tweak
      ) {
        this.setState({
          seckey: this.props.seckey,
          tweak: this.props.tweak,
        });
      }

      if (
        prevState.seckey !== this.state.seckey ||
        prevState.tweak !== this.state.tweak
      ) {
        const { seckey, tweak } = this.state;
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const tweak_valid = tweak === "" ? undefined : validate.isTweak(tweak);
        const result =
          seckey === "" && tweak === ""
            ? undefined
            : secp256k1.privateSub(seckey, tweak);
        this.setState({ seckey_valid, tweak_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            privateSub(d: Uint8Array, tweak: Uint8Array) =&gt; Uint8Array | null
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Tweak as HEX string"
            onChange={createInputChange(this, "tweak")}
            value={this.state.tweak}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.tweak_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Output, Private Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiPrivateNegate = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        seckey: "",
        seckey_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (prevProps.seckey !== this.props.seckey) {
        this.setState({
          seckey: this.props.seckey,
        });
      }

      if (prevState.seckey !== this.state.seckey) {
        const { seckey } = this.state;
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const result =
          seckey === "" ? undefined : secp256k1.privateNegate(seckey);
        this.setState({ seckey_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            privateNegate(d: Uint8Array, tweak: Uint8Array) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />

          <TextField
            label="Output, Negated Private Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiSign = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        seckey: "",
        seckey_valid: undefined,
        entropy: "",
        entropy_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.seckey !== this.props.seckey ||
        prevProps.entropy !== this.props.entropy
      ) {
        this.setState({
          hash: this.props.hash,
          seckey: this.props.seckey,
          entropy: this.props.entropy,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.seckey !== this.state.seckey ||
        prevState.entropy !== this.state.entropy
      ) {
        const { hash, seckey, entropy } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const entropy_valid =
          entropy === "" ? undefined : validate.isExtraData(entropy);
        const result =
          hash === "" && seckey === "" && entropy === ""
            ? undefined
            : secp256k1.sign(hash, seckey, entropy);
        this.setState({ hash_valid, seckey_valid, entropy_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            sign(h: Uint8Array, d: Uint8Array, e: Uint8Array) =&gt; Uint8Array
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Extra Data as HEX string"
            onChange={createInputChange(this, "entropy")}
            value={this.state.entropy}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.entropy_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Output, Signature as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiSignRecoverable = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        seckey: "",
        seckey_valid: undefined,
        entropy: "",
        entropy_valid: undefined,
        result: undefined,
        resultRecId: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.seckey !== this.props.seckey ||
        prevProps.entropy !== this.props.entropy
      ) {
        this.setState({
          hash: this.props.hash,
          seckey: this.props.seckey,
          entropy: this.props.entropy,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.seckey !== this.state.seckey ||
        prevState.entropy !== this.state.entropy
      ) {
        const { hash, seckey, entropy } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const entropy_valid =
          entropy === "" ? undefined : validate.isExtraData(entropy);
        const sig =
          hash === "" && seckey === "" && entropy === ""
            ? undefined
            : secp256k1.signRecoverable(hash, seckey, entropy);
        const result = toHex(sig?.signature);
        const resultRecId = sig?.recoveryId;
        this.setState({
          hash_valid,
          seckey_valid,
          entropy_valid,
          result,
          resultRecId,
        });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            signRecoverable(h: Uint8Array, d: Uint8Array, e: Uint8Array) =&gt;
            (Uint8Array, recoveryId: 0 | 1 | 2 | 3)
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Extra Data as HEX string"
            onChange={createInputChange(this, "entropy")}
            value={this.state.entropy}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.entropy_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Output, Signature as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
          <TextField
            label="Output, Recovery Id as number"
            value={
              this.state.resultRecId === undefined
                ? ""
                : this.state.resultRecId || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
          />
        </>
      );
    }
  }
);

const ApiVerify = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        pubkey: "",
        pubkey_valid: undefined,
        signature: "",
        signature_valid: undefined,
        strict: false,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.pubkey !== this.props.pubkey ||
        prevProps.signature !== this.props.signature
      ) {
        this.setState({
          hash: this.props.hash,
          pubkey: this.props.pubkey,
          signature: this.props.signature,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.pubkey !== this.state.pubkey ||
        prevState.signature !== this.state.signature
      ) {
        const { hash, pubkey, signature } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const pubkey_valid =
          pubkey === "" ? undefined : secp256k1.isPoint(pubkey);
        const signature_valid =
          signature === "" ? undefined : validate.isSignature(signature);
        const result =
          hash === "" && pubkey === "" && signature === ""
            ? undefined
            : secp256k1.verify(hash, pubkey, signature);
        this.setState({ hash_valid, pubkey_valid, signature_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            verify(h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict:
            boolean) =&gt; boolean
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "pubkey")}
            value={this.state.pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.pubkey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Signature as HEX string"
            onChange={createInputChange(this, "signature")}
            value={this.state.signature}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.signature_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "strict")}
                checked={this.state.strict}
              />
            }
            label="Strict"
          />
          {this.state.result !== undefined && (
            <Box align="center">
              {this.state.result ? <CheckIcon /> : <CloseIcon color="error" />}
            </Box>
          )}
        </>
      );
    }
  }
);

const ApiRecover = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        signature: "",
        signature_valid: undefined,
        recoveryId: 0,
        recoveryId_valid: undefined,
        compressed: false,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.signature !== this.props.signature ||
        prevProps.recoveryId !== this.props.recoveryId ||
        prevProps.compressed !== this.props.compressed
      ) {
        this.setState({
          hash: this.props.hash,
          signature: this.props.signature,
          recoveryId: this.props.recoveryId,
          compressed: this.props.compressed,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.signature !== this.state.signature ||
        prevState.recoveryId !== this.state.recoveryId ||
        prevState.compressed !== this.state.compressed
      ) {
        const { hash, signature, recoveryId, compressed } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const recoveryId_valid =
          recoveryId === "" ? undefined : 0 <= +recoveryId <= 3;
        const signature_valid =
          signature === "" ? undefined : validate.isSignature(signature);
        const result =
          hash === "" && recoveryId === "" && signature === ""
            ? undefined
            : secp256k1.recover(hash, signature, recoveryId, compressed);
        this.setState({
          hash_valid,
          signature_valid,
          recoveryId_valid,
          result,
        });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            recover(h: Uint8Array, signature: Uint8Array, recoveryId: number,
            compressed?: boolean) =&gt; Uint8Array | null
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Signature as HEX string"
            onChange={createInputChange(this, "signature")}
            value={this.state.signature}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.signature_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Recovery Id (0, 1, 2 or 3)"
            type="number"
            onChange={createInputChange(this, "recoveryId")}
            value={this.state.recoveryId}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.recoveryId_valid,
              this.props.classes
            )}
          />
          <FormControlLabel
            control={
              <CompressedCheckbox
                onChange={createCheckedChange(this, "compressed")}
                checked={this.state.compressed}
              />
            }
            label="Compressed"
          />
          <TextField
            label="Output, Public Key as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiSignSchnorr = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        seckey: "",
        seckey_valid: undefined,
        entropy: "",
        entropy_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.seckey !== this.props.seckey ||
        prevProps.entropy !== this.props.entropy
      ) {
        this.setState({
          hash: this.props.hash,
          seckey: this.props.seckey,
          entropy: this.props.entropy,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.seckey !== this.state.seckey ||
        prevState.entropy !== this.state.entropy
      ) {
        const { hash, seckey, entropy } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const entropy_valid =
          entropy === "" ? undefined : validate.isExtraData(entropy);
        const result =
          hash === "" && seckey === "" && entropy === ""
            ? undefined
            : secp256k1.signSchnorr(hash, seckey, entropy);
        this.setState({ hash_valid, seckey_valid, entropy_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            signSchnorr(h: Uint8Array, d: Uint8Array, e: Uint8Array) =&gt;
            Uint8Array
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Private Key as HEX string"
            onChange={createInputChange(this, "seckey")}
            value={this.state.seckey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.seckey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Extra Data as HEX string"
            onChange={createInputChange(this, "entropy")}
            value={this.state.entropy}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.entropy_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Output, Signature as HEX string"
            value={
              this.state.result === undefined
                ? ""
                : this.state.result || "Invalid result"
            }
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(this.state.result, this.props.classes)}
          />
        </>
      );
    }
  }
);

const ApiVerifySchnorr = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        x_only_pubkey: "",
        x_only_pubkey_valid: undefined,
        schnorr_signature: "",
        schnorr_signature_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.x_only_pubkey !== this.props.x_only_pubkey ||
        prevProps.schnorr_signature !== this.props.schnorr_signature
      ) {
        this.setState({
          hash: this.props.hash,
          x_only_pubkey: this.props.x_only_pubkey,
          schnorr_signature: this.props.schnorr_signature,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.x_only_pubkey !== this.state.x_only_pubkey ||
        prevState.schnorr_signature !== this.state.schnorr_signature
      ) {
        const { hash, x_only_pubkey, schnorr_signature } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const x_only_pubkey_valid =
          x_only_pubkey === ""
            ? undefined
            : secp256k1.isXOnlyPoint(x_only_pubkey);
        const schnorr_signature_valid =
          schnorr_signature === ""
            ? undefined
            : validate.isSignature(schnorr_signature);
        const result =
          hash === "" && x_only_pubkey === "" && schnorr_signature === ""
            ? undefined
            : secp256k1.verifySchnorr(hash, x_only_pubkey, schnorr_signature);
        this.setState({
          hash_valid,
          x_only_pubkey_valid,
          schnorr_signature_valid,
          result,
        });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            verifySchnorr(h: Uint8Array, Q: Uint8Array, signature: Uint8Array)
            =&gt; boolean
          </Typography>
          <TextField
            label="Hash as HEX string"
            onChange={createInputChange(this, "hash")}
            value={this.state.hash}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.hash_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Public Key as HEX string"
            onChange={createInputChange(this, "x_only_pubkey")}
            value={this.state.x_only_pubkey}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.x_only_pubkey_valid,
              this.props.classes
            )}
          />
          <TextField
            label="Signature as HEX string"
            onChange={createInputChange(this, "schnorr_signature")}
            value={this.state.schnorr_signature}
            fullWidth
            margin="normal"
            variant="outlined"
            InputProps={getInputProps(
              this.state.schnorr_signature_valid,
              this.props.classes
            )}
          />
          {this.state.result !== undefined && (
            <Box align="center">
              {this.state.result ? <CheckIcon /> : <CloseIcon color="error" />}
            </Box>
          )}
        </>
      );
    }
  }
);

ReactDOM.render(<App />, document.getElementById("app"));
