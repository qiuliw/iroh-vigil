//! 冒烟入口:起一个 vigil 节点,打印 node_id,Ctrl-C 退出。

use iroh_vigil::Builder;

#[tokio::main]
async fn main() -> Result<(), iroh_vigil::VigilError> {
    let node = Builder::new().spawn().await?;
    println!("iroh-vigil node: {}", node.node_id());
    tokio::signal::ctrl_c().await.expect("ctrl-c listener");
    node.shutdown().await
}
