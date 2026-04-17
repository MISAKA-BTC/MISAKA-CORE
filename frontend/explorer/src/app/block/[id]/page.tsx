import BlockClient from "./BlockClient";

export function generateStaticParams() {
  return [{ id: "[id]" }];
}

export default function BlockDetail({ params }: { params: { id: string } }) {
  return <BlockClient id={params.id} />;
}
