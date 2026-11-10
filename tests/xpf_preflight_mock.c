#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *const expected_names[] = {
	"kernelConstant.T1SZ_BOOT",
	"kernelStruct.task.itk_space",
	"kernelStruct.proc.struct_size",
	"kernelSymbol.allproc",
};

static const uint64_t expected_values[] = {
	UINT64_C(0x5a),
	UINT64_C(0x1234),
	UINT64_C(0x5678),
	UINT64_C(0x1111222233334444),
};

static unsigned int resolve_index;
static const char *mock_error;

int xpf_start_with_kernel_path(const char *kernel_path)
{
	if (getenv("XPF_MOCK_START_FAIL") != NULL) {
		mock_error = "mock initialization failure";
		return -1;
	}
	if (kernel_path == NULL || kernel_path[0] == '\0') {
		mock_error = "mock kernel path missing";
		return -1;
	}
	return 0;
}

uint64_t xpf_item_resolve(const char *name)
{
	if (resolve_index >= sizeof(expected_names) / sizeof(expected_names[0]) ||
	    strcmp(name, expected_names[resolve_index]) != 0) {
		mock_error = "XPF metric name/order mismatch";
		return 0;
	}
	const char *fail_index = getenv("XPF_MOCK_FAIL_INDEX");
	if (fail_index != NULL && strtoul(fail_index, NULL, 10) == resolve_index) {
		resolve_index++;
		mock_error = "mock finder failure";
		return 0;
	}
	return expected_values[resolve_index++];
}

const char *xpf_get_error(void)
{
	return mock_error;
}

void xpf_stop(void)
{
}
