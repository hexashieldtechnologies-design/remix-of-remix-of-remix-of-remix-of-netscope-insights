CREATE TABLE public.relay_frames (
  id bigserial PRIMARY KEY,
  room text NOT NULL,
  kind text NOT NULL DEFAULT 'frame',
  payload text NOT NULL,
  ts double precision,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT ALL ON public.relay_frames TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.relay_frames_id_seq TO service_role;
ALTER TABLE public.relay_frames ENABLE ROW LEVEL SECURITY;
CREATE INDEX relay_frames_room_id_idx ON public.relay_frames (room, id);
CREATE INDEX relay_frames_created_idx ON public.relay_frames (created_at);