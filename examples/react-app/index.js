import { Buffer } from "buffer";
import ReactDOM from "react-dom";
import React, { Component } from "react";
import Box from "@material-ui/core/Box";
import Button from "@material-ui/core/Button";
import CheckIcon from "@material-ui/icons/Check";
import Checkbox from "@material-ui/core/Checkbox";
import CloseIcon from "@material-ui/icons/Close";
import CssBaseline from "@material-ui/core/CssBaseline";
import FormControlLabel from "@material-ui/core/FormControlLabel";
import Paper from "@material-ui/core/Paper";
import TextField from "@material-ui/core/TextField";
import Typography from "@material-ui/core/Typography";
import { withStyles } from "@material-ui/core/styles";

import * as _secp256k1 from "../../";
import * as _validate from "../../lib/validate.js";
import { generate } from "../random-in-node";

const EMPTY_BUFFER = Buffer.allocUnsafe(0);
function toUint8Array(value) {
  if (typeof value !== "string") return value;
  const data = Buffer.from(value, "hex");
  return data.toString("hex") === value ? data : EMPTY_BUFFER;
}

const validate = {
  _throw2bool(method, v) {
    try {
      _validate[method](toUint8Array(v));
      return true;
    } catch (_err) {
      return false;
    }
  },
  isTweak: (v) => validate._throw2bool("validateTweak", v),
  isHash: (v) => validate._throw2bool("validateHash", v),
  isExtraData: (v) => validate._throw2bool("validateExtraData", v),
  isSignature: (v) => validate._throw2bool("validateSignature", v),
};
const secp256k1 = {
  _throw2null(method, args) {
    try {
      let result = _secp256k1[method](...args.map((v) => toUint8Array(v)));
      if (result instanceof Uint8Array) {
        result = Buffer.from(result).toString("hex");
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
        data[key] = Buffer.from(data[key]).toString("hex");
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
                <ApiSign
                  classes={this.props.classes}
                  hash={this.state.data?.hash}
                  seckey={this.state.data?.seckey}
                />
              </Box>
              <Box className={this.props.classes.methodBox}>
                <ApiSignWithEntropy
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
            label="Public Key as HEX string"
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

const ApiSign = withStyles(useStyles)(
  class extends Component {
    constructor(props) {
      super(props);
      this.state = {
        hash: "",
        hash_valid: undefined,
        seckey: "",
        seckey_valid: undefined,
        result: undefined,
      };
    }

    componentDidUpdate(prevProps, prevState) {
      if (
        prevProps.hash !== this.props.hash ||
        prevProps.seckey !== this.props.seckey
      ) {
        this.setState({
          hash: this.props.hash,
          seckey: this.props.seckey,
        });
      }

      if (
        prevState.hash !== this.state.hash ||
        prevState.seckey !== this.state.seckey
      ) {
        const { hash, seckey } = this.state;
        const hash_valid = hash === "" ? undefined : validate.isHash(hash);
        const seckey_valid =
          seckey === "" ? undefined : secp256k1.isPrivate(seckey);
        const result =
          hash === "" && seckey === ""
            ? undefined
            : secp256k1.sign(hash, seckey);
        this.setState({ hash_valid, seckey_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            sign(h: Uint8Array, d: Uint8Array) =&gt; Uint8Array
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

const ApiSignWithEntropy = withStyles(useStyles)(
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
            : secp256k1.signWithEntropy(hash, seckey, entropy);
        this.setState({ hash_valid, seckey_valid, entropy_valid, result });
      }
    }

    render() {
      return (
        <>
          <Typography variant="h6">
            signWithEntropy(h: Uint8Array, d: Uint8Array, e: Uint8Array) =&gt;
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

ReactDOM.render(<App />, document.getElementById("app"));
