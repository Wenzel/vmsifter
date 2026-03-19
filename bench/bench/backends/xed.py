"""Intel XED decoder backend using CFFI bindings."""

from _xed_cffi import ffi, lib  # type: ignore[import-not-found]

from bench.backends.base import register
from bench.schema import Backend, BackendResult

_MODE_MAP = {
    32: (lib.XED_MACHINE_MODE_LEGACY_32, lib.XED_ADDRESS_WIDTH_32b),
    64: (lib.XED_MACHINE_MODE_LONG_64, lib.XED_ADDRESS_WIDTH_64b),
}


@register
class XedBackend(Backend):
    name = "xed"
    kind = "decoder"

    def setup(self) -> None:
        lib.xed_tables_init()
        self._state = ffi.new("xed_state_t *")
        self._xedd = ffi.new("xed_decoded_inst_t *")
        self._buf = ffi.new("char[256]")
        self._mode: int | None = None

    def _set_mode(self, exec_mode: int) -> None:
        if exec_mode not in _MODE_MAP:
            raise ValueError(f"Unsupported exec_mode {exec_mode}; expected 32 or 64")
        machine_mode, addr_width = _MODE_MAP[exec_mode]
        lib.xed_state_init2(self._state, machine_mode, addr_width)
        self._mode = exec_mode

    def process(self, insn_bytes: bytes, exec_mode: int) -> BackendResult:
        if exec_mode != self._mode:
            self._set_mode(exec_mode)

        lib.xed_decoded_inst_zero_set_mode(self._xedd, self._state)
        err = lib.xed_decode(self._xedd, insn_bytes, len(insn_bytes))

        if err != lib.XED_ERROR_NONE:
            error_str = ffi.string(lib.xed_error_enum_t2str(err)).decode()
            return BackendResult(
                valid=False,
                length=None,
                exit_type="invalid",
                misc={"error": error_str},
            )

        length = lib.xed_decoded_inst_get_length(self._xedd)

        # Format disassembly
        asm = None
        if lib.xed_format_context(
            lib.XED_SYNTAX_INTEL, self._xedd, self._buf, 256, 0x1000, ffi.NULL, ffi.NULL
        ):
            asm = ffi.string(self._buf).decode()

        return BackendResult(
            valid=True,
            length=length,
            exit_type="valid",
            misc={"asm": asm} if asm else None,
        )

    def teardown(self) -> None:
        self._state = None
        self._xedd = None
        self._buf = None
        self._mode = None
