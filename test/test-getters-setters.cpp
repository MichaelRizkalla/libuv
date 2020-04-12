#include "uv.h"
#include "task.h"
#include <string.h>
#include <sys/stat.h>
#include "utils/allocator.cpp"
int cookie1;
int cookie2;
int cookie3;


TEST_IMPL(handle_type_name) {
  ASSERT(strcmp(uv_handle_type_name(UV_NAMED_PIPE), "pipe") == 0);
  ASSERT(strcmp(uv_handle_type_name(UV_UDP), "udp") == 0);
  ASSERT(strcmp(uv_handle_type_name(UV_FILE), "file") == 0);
  ASSERT(uv_handle_type_name(UV_HANDLE_TYPE_MAX) == nullptr);
  ASSERT(uv_handle_type_name(static_cast<uv_handle_type>(static_cast<int>(UV_HANDLE_TYPE_MAX) + 1)) == nullptr);
  ASSERT(uv_handle_type_name(UV_UNKNOWN_HANDLE) == nullptr);
  return 0;
}


TEST_IMPL(req_type_name) {
  ASSERT(strcmp(uv_req_type_name(UV_REQ), "req") == 0);
  ASSERT(strcmp(uv_req_type_name(UV_UDP_SEND), "udp_send") == 0);
  ASSERT(strcmp(uv_req_type_name(UV_WORK), "work") == 0);
  ASSERT(uv_req_type_name(UV_REQ_TYPE_MAX) == nullptr);
  ASSERT(uv_req_type_name(static_cast<uv_req_type>(static_cast<int>(UV_REQ_TYPE_MAX) + 1)) == nullptr);
  ASSERT(uv_req_type_name(UV_UNKNOWN_REQ) == nullptr);
  return 0;
}


TEST_IMPL(getters_setters) {
  uv_loop_t* loop;
  uv_pipe_t* pipe;
  uv_fs_t* fs;
  int r;

  loop = test_create_ptrstruct<uv_loop_t>(uv_loop_size());
  ASSERT(loop != nullptr);
  r = uv_loop_init(loop);
  ASSERT(r == 0);

  uv_loop_set_data(loop, &cookie1);
  ASSERT(loop->data == &cookie1);
  ASSERT(uv_loop_get_data(loop) == &cookie1);

  pipe = test_create_ptrstruct<uv_pipe_t>(uv_handle_size(UV_NAMED_PIPE));
  r = uv_pipe_init(loop, pipe, 0);
  ASSERT(uv_handle_get_type((uv_handle_t*)pipe) == UV_NAMED_PIPE);

  ASSERT(uv_handle_get_loop((uv_handle_t*)pipe) == loop);
  pipe->data = &cookie2;
  ASSERT(uv_handle_get_data((uv_handle_t*)pipe) == &cookie2);
  uv_handle_set_data((uv_handle_t*)pipe, &cookie1);
  ASSERT(uv_handle_get_data((uv_handle_t*)pipe) == &cookie1);
  ASSERT(pipe->data == &cookie1);

  ASSERT(uv_stream_get_write_queue_size((uv_stream_t*)pipe) == 0);
  pipe->write_queue_size++;
  ASSERT(uv_stream_get_write_queue_size((uv_stream_t*)pipe) == 1);
  pipe->write_queue_size--;
  uv_close((uv_handle_t*)pipe, nullptr);

  r = uv_run(loop, UV_RUN_DEFAULT);
  ASSERT(r == 0);

  fs = test_create_ptrstruct<uv_fs_t>(uv_req_size(UV_FS));
  uv_fs_stat(loop, fs, ".", nullptr);

  r = uv_run(loop, UV_RUN_DEFAULT);
  ASSERT(r == 0);

  ASSERT(uv_fs_get_type(fs) == UV_FS_STAT);
  ASSERT(uv_fs_get_result(fs) == 0);
  ASSERT(uv_fs_get_ptr(fs) == uv_fs_get_statbuf(fs));
  ASSERT(uv_fs_get_statbuf(fs)->st_mode & S_IFDIR);
  ASSERT(strcmp(uv_fs_get_path(fs), ".") == 0);
  uv_fs_req_cleanup(fs);

  r = uv_loop_close(loop);
  ASSERT(r == 0);

  free(pipe);
  free(fs);
  free(loop);
  return 0;
}
